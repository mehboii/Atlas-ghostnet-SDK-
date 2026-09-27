import { createIdentity, loadIdentity } from './crypto/identity.js';
import { encrypt, decrypt, edPrivateToX25519, edPublicToX25519 } from './crypto/encryption.js';
import { sign, verify } from './crypto/signing.js';
import {
  ConnectionError,
  PeerNotFoundError,
  PayloadTooLargeError,
  PeerVerificationError,
  IdentityError,
  EncryptionError,
  RelayError,
} from './errors.js';
import { Logger } from './logger.js';
import { Transport } from './transport.js';
import { endpointOrigin } from './endpoint.js';
import type { GhostNetOptions, GhostNetEvents, Identity, IncomingMessage, SecurityEvent, PeerInfo, NetworkStatus } from './types.js';
import { hexToBytes, bytesToHex, randomBytes } from '@noble/hashes/utils';
import { blake3 } from '@noble/hashes/blake3';

const DEFAULT_ENDPOINT = 'wss://ghostnet-ji-production.up.railway.app';
const MAX_MESSAGE_BYTES = 64 * 1024; // 64 KB max message payload
const NONCE_REGISTRY_MAX = 10_000;   // Max tracked nonces before time-based eviction
const MESSAGE_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes — reject older messages
const SIGNATURE_VERSION = 'v1';

/**
 * Main Atlas SDK client.
 *
 * Creates or restores an identity, connects to the GhostNet mesh relay,
 * and lets you send/receive end-to-end encrypted messages.
 *
 * @example
 * ```ts
 * import { GhostNet } from '@n11x/atlas';
 *
 * const gn = new GhostNet({ debug: true });
 * const identity = gn.createIdentity();
 * await gn.connect();
 * gn.on('message', (msg) => console.log(msg.from, msg.data));
 * await gn.send(peerId, 'hello from the mesh');
 * gn.disconnect();
 * ```
 */
export class GhostNet {
  private readonly endpoint: string;
  private readonly logger: Logger;
  private readonly requireEncryption: boolean;
  private transport: Transport | null = null;
  private connecting: Promise<void> | null = null;
  private identity: Identity | null = null;
  /** Maps peer nodeId → raw 32-byte Ed25519 public key, verified via signature. */
  private peerKeys: Map<string, Uint8Array> = new Map();
  private peerInfo: Map<string, PeerInfo> = new Map();
  /** Maps seen nonce (hex) → timestamp for time-based replay detection. */
  private seenNonces: Map<string, number> = new Map();
  private listeners: { [K in keyof GhostNetEvents]: Set<GhostNetEvents[K]> } = {
    message: new Set(),
    error: new Set(),
    connect: new Set(),
    disconnect: new Set(),
    security: new Set(),
    'peer:discovered': new Set(),
  };

  constructor(options: GhostNetOptions = {}) {
    const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
    this.endpoint = GhostNet.validateEndpoint(endpoint);
    this.logger = new Logger(options.debug ?? false);
    this.requireEncryption = options.requireEncryption ?? true;
  }

  /**
   * Validate and sanitize a WebSocket endpoint URL.
   * Rejects insecure protocols, embedded credentials, and suspicious paths.
   */
  private static validateEndpoint(endpoint: string): string {
    if (!endpoint.startsWith('wss://')) {
      throw new ConnectionError(
        'Insecure WebSocket endpoint rejected. Use wss:// for encrypted connections.',
      );
    }

    let parsed: URL;
    try {
      parsed = new URL(endpoint);
    } catch {
      throw new ConnectionError('Invalid endpoint URL');
    }

    if (parsed.username || parsed.password) {
      throw new ConnectionError(
        'Endpoint URL must not contain credentials — they leak in logs and referrer headers.',
      );
    }

    if (endpoint.includes('..')) {
      throw new ConnectionError(
        'Endpoint URL contains path traversal sequence.',
      );
    }

    return endpoint;
  }

  // ── Identity ──────────────────────────────────────────────────────

  /**
   * Generate a brand-new GhostNet identity (BIP-39 seed phrase + Ed25519 keypair).
   *
   * The returned seed phrase is the master secret. Back it up safely — it is the
   * only way to restore this identity on another device.
   *
   * @returns The newly created {@link Identity}.
   */
  createIdentity(): Identity {
    this.identity = createIdentity();
    this.logger.debug(`Identity created: ${this.identity.nodeId}`);
    return this.identity;
  }

  /**
   * Restore a GhostNet identity from an existing BIP-39 seed phrase.
   *
   * Produces the same keypair and node ID every time, so identities are
   * portable across devices and SDK versions.
   *
   * @param seedPhrase - A valid 12-word BIP-39 mnemonic.
   * @returns The restored {@link Identity}.
   * @throws {IdentityError} If the seed phrase is invalid.
   */
  loadIdentity(seedPhrase: string): Identity {
    this.identity = loadIdentity(seedPhrase);
    this.logger.debug(`Identity loaded: ${this.identity.nodeId}`);
    return this.identity;
  }

  /**
   * Get the current identity, or null if none has been created/loaded.
   */
  getIdentity(): Identity | null {
    return this.identity;
  }

  /** Public identity only; safe to serialize. */
  getPublicIdentity(): { nodeId: string; publicKey: string } | null {
    return this.identity ? { nodeId: this.identity.nodeId, publicKey: this.identity.publicKey } : null;
  }

  /** Locally known peer keys. An entry does not prove that a peer is online. */
  listPeers(): PeerInfo[] {
    return Array.from(this.peerInfo.values(), (peer) => ({ ...peer }));
  }

  /** Add a recipient key obtained through a trusted out-of-band channel. */
  addPeer(publicKey: string): PeerInfo {
    if (!/^[0-9a-f]{64}$/.test(publicKey)) {
      throw new PeerVerificationError('unknown', 'expected a 32-byte lowercase hex Ed25519 public key');
    }
    const key = hexToBytes(publicKey);
    const nodeId = '0x' + bytesToHex(blake3(key));
    this.rememberPeer(nodeId, key, 'manual');
    return { ...this.peerInfo.get(nodeId)! };
  }

  /** Local WebSocket and identity state. No relay-side health claim is implied. */
  getStatus(): NetworkStatus {
    return {
      connected: this.transport?.connected ?? false,
      endpoint: endpointOrigin(this.endpoint),
      nodeId: this.identity?.nodeId ?? null,
      knownPeers: this.peerInfo.size,
    };
  }

  // ── Connection ────────────────────────────────────────────────────

  /**
   * Connect to the GhostNet mesh relay over WebSocket.
   *
   * An identity must be created or loaded before calling this method.
   * The client sends its public key, node ID, and signed announcement to the relay.
   * This package does not establish whether the relay verifies registration.
   *
   * @throws {ConnectionError} If no identity is set or the connection fails.
   */
  async connect(): Promise<void> {
    if (!this.identity) {
      throw new ConnectionError('Create or load an identity before connecting');
    }

    if (this.transport?.connected) return;
    if (this.connecting) return this.connecting;
    this.transport?.disconnect();

    this.transport = new Transport(this.endpoint, this.logger);

    this.transport.on('open', () => {
      const announce = new TextEncoder().encode(`ghostnet:announce:${this.identity!.nodeId}`);
      this.transport!.send(JSON.stringify({
        type: 'register',
        nodeId: this.identity!.nodeId,
        publicKey: this.identity!.publicKey,
        signature: bytesToHex(sign(announce, this.identity!.privateKeyBytes)),
      }));
      this.emit('connect');
    });

    this.transport.on('close', (reason) => {
      this.emit('disconnect', reason);
    });

    this.transport.on('error', (err) => {
      this.emit('error', err);
    });

    this.transport.on('message', (data) => {
      this.handleIncoming(data).catch((err: unknown) => {
        this.emit('error', err instanceof Error ? err : new Error(String(err)));
      });
    });

    const pending = this.transport.connect();
    this.connecting = pending;
    try {
      await pending;
    } catch (error) {
      this.transport?.disconnect();
      this.transport = null;
      throw error;
    } finally {
      this.connecting = null;
    }
  }

  /**
   * Disconnect from the GhostNet relay.
   *
   * Safe to call even if not connected. Does not clear the identity.
   */
  disconnect(): void {
    this.transport?.disconnect();
    this.transport = null;
    this.logger.debug('Disconnected');
  }

  // ── Messaging ─────────────────────────────────────────────────────

  /**
   * Send an end-to-end encrypted, signed message to a peer by node ID.
   *
   * The message is encrypted with the recipient's public key using hybrid
   * encryption (X25519 ECDH + AES-256-GCM) and signed with Ed25519.
   * The relay cannot read or forge messages.
   *
   * @param peerId  - The recipient's node ID (0x-prefixed BLAKE3 hash).
   * @param message - The plaintext message string.
   * @throws {ConnectionError} If not connected.
   * @throws {PeerNotFoundError} If peer key is unknown and requireEncryption is true.
   * @throws {EncryptionError} If encryption fails.
   */
  async send(peerId: string, message: string): Promise<void> {
    if (!this.identity) {
      throw new IdentityError('Create or load an identity before sending messages');
    }

    try {
      void this.identity.seedPhrase;
    } catch {
      throw new IdentityError('Identity has been disposed — cannot send messages');
    }

    const transport = this.transport;
    if (!transport?.connected) {
      throw new ConnectionError('Not connected — call .connect() first');
    }

    const messageBytes = new TextEncoder().encode(message);
    if (messageBytes.byteLength > MAX_MESSAGE_BYTES) {
      throw new PayloadTooLargeError(messageBytes.byteLength, MAX_MESSAGE_BYTES);
    }

    if (!/^0x[0-9a-f]{64}$/.test(peerId)) {
      throw new PeerVerificationError(peerId, 'invalid node ID');
    }

    this.logger.debug(`Sending to ${peerId}: ${message.length} chars`);

    const nonce = bytesToHex(randomBytes(16));
    const timestamp = Date.now();

    const peerPubBytes = this.peerKeys.get(peerId);

    if (!peerPubBytes) {
      if (this.requireEncryption) {
        throw new PeerNotFoundError(peerId);
      }

      this.emitSecurity(
        'plaintext_fallback',
        `No verified key for peer ${peerId} — sending without E2E encryption`,
        peerId,
      );

      const payload = message;
      const sig = this.signEnvelope(nonce, timestamp, this.identity!.nodeId, peerId, payload);

      transport.send(JSON.stringify({
        type: 'message',
        from: this.identity!.nodeId,
        to: peerId,
        payload,
        encrypted: false,
        nonce,
        timestamp,
        signature: sig,
        senderPublicKey: this.identity!.publicKey,
      }));
      return;
    }

    const peerX25519Pub = edPublicToX25519(peerPubBytes);
    const encryptedPayload = encrypt(message, peerX25519Pub);
    const payloadBase64 = uint8ToBase64(encryptedPayload);
    const sig = this.signEnvelope(nonce, timestamp, this.identity!.nodeId, peerId, payloadBase64);

    transport.send(JSON.stringify({
      type: 'message',
      from: this.identity!.nodeId,
      to: peerId,
      payload: payloadBase64,
      encrypted: true,
      nonce,
      timestamp,
      signature: sig,
      senderPublicKey: this.identity!.publicKey,
    }));
  }

  // ── Events ────────────────────────────────────────────────────────

  /**
   * Subscribe to a GhostNet event.
   *
   * @param event   - Event name: "message", "error", "connect", "disconnect", or "security".
   * @param handler - Callback invoked when the event fires.
   */
  on<K extends keyof GhostNetEvents>(event: K, handler: GhostNetEvents[K]): void {
    this.listeners[event].add(handler);
  }

  /**
   * Unsubscribe from a GhostNet event.
   *
   * @param event   - Event name.
   * @param handler - The same function reference passed to {@link on}.
   */
  off<K extends keyof GhostNetEvents>(event: K, handler: GhostNetEvents[K]): void {
    this.listeners[event].delete(handler);
  }

  /** Subscribe and receive a cleanup function. */
  subscribe<K extends keyof GhostNetEvents>(event: K, handler: GhostNetEvents[K]): () => void {
    this.on(event, handler);
    return () => this.off(event, handler);
  }

  private rememberPeer(nodeId: string, key: Uint8Array, source: PeerInfo['source']): void {
    const known = this.peerInfo.has(nodeId);
    this.peerKeys.set(nodeId, key);
    const peer = { nodeId, publicKey: bytesToHex(key), lastSeen: source === 'manual' ? null : Date.now(), source };
    this.peerInfo.set(nodeId, peer);
    if (!known) this.emit('peer:discovered', { ...peer });
  }

  // ── Internals ─────────────────────────────────────────────────────

  /**
   * Produce an Ed25519 signature hex over the canonical message envelope.
   */
  private signEnvelope(
    nonce: string,
    timestamp: number,
    from: string,
    to: string,
    payload: string,
  ): string {
    const payloadHash = bytesToHex(blake3(new TextEncoder().encode(payload)));
    const canonical = new TextEncoder().encode(
      `ghostnet:msg:${SIGNATURE_VERSION}:${nonce}:${timestamp}:${from}:${to}:${payloadHash}`,
    );
    return bytesToHex(sign(canonical, this.identity!.privateKeyBytes));
  }

  /**
   * Check and record a message nonce. Returns false if replayed.
   * Uses time-based expiration (instead of count-based eviction) to prevent
   * nonce-flood replay attacks, with a hard cap as a memory safety net.
   *
   * Call this only after a message has passed freshness and signature
   * checks, so the registry is never polluted by forged or stale traffic.
   */
  private checkNonce(nonce: string, timestamp: number): boolean {
    if (this.seenNonces.has(nonce)) {
      return false;
    }

    // Time-based eviction: remove nonces older than the freshness window.
    if (this.seenNonces.size >= NONCE_REGISTRY_MAX / 2) {
      const now = Date.now();
      for (const [n, t] of this.seenNonces) {
        if (now - t > MESSAGE_MAX_AGE_MS) {
          this.seenNonces.delete(n);
        }
      }
    }

    // Hard cap: under sustained high throughput, many nonces may still be
    // within the freshness window and survive the sweep above. Evict the
    // oldest entries (Map preserves insertion order) to bound memory.
    while (this.seenNonces.size >= NONCE_REGISTRY_MAX) {
      const oldest = this.seenNonces.keys().next().value;
      if (oldest === undefined) break;
      this.seenNonces.delete(oldest);
    }

    this.seenNonces.set(nonce, timestamp);
    return true;
  }

  /**
   * Verify a peer_announce message signature.
   *
   * The announce must include:
   *   - nodeId: claimed node ID
   *   - publicKey: hex-encoded Ed25519 public key
   *   - signature: hex-encoded Ed25519 signature over "ghostnet:announce:<nodeId>"
   *
   * We verify that:
   *   1. The signature is valid for the claimed public key
   *   2. The nodeId is the BLAKE3 hash of the public key (binding)
   *   3. TOFU: if we already have a key for this peer, it must match
   */
  private verifyPeerAnnounce(
    nodeId: string,
    publicKeyHex: string,
    signatureHex: string,
  ): Uint8Array | null {
    if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) {
      this.logger.warn(`Invalid public key format from peer ${nodeId}`);
      return null;
    }
    if (!/^[0-9a-f]{128}$/.test(signatureHex)) {
      this.logger.warn(`Invalid signature format from peer ${nodeId}`);
      return null;
    }

    const pubBytes = hexToBytes(publicKeyHex);
    const sigBytes = hexToBytes(signatureHex);

    const expectedNodeId = '0x' + bytesToHex(blake3(pubBytes));
    if (expectedNodeId !== nodeId) {
      this.logger.warn(`Peer ${nodeId}: public key does not match node ID (expected ${expectedNodeId})`);
      return null;
    }

    const announceMsg = new TextEncoder().encode(`ghostnet:announce:${nodeId}`);
    if (!verify(sigBytes, announceMsg, pubBytes)) {
      this.logger.warn(`Peer ${nodeId}: invalid signature on announce`);
      return null;
    }

    // TOFU: reject key changes for known peers
    const existingKey = this.peerKeys.get(nodeId);
    if (existingKey && bytesToHex(existingKey) !== publicKeyHex) {
      this.emitSecurity(
        'peer_key_changed',
        `Peer ${nodeId} announced a different public key — rejecting (TOFU violation)`,
        nodeId,
      );
      return null;
    }

    return pubBytes;
  }

  /**
   * Verify an Ed25519 signature on an incoming message envelope.
   * Also performs TOFU key pinning when signature is valid.
   */
  private verifyMessageSignature(envelope: {
    from?: string;
    to?: string;
    nonce?: string;
    timestamp?: number;
    payload?: string;
    signature?: string;
    senderPublicKey?: string;
  }): boolean {
    if (
      !envelope.senderPublicKey ||
      !envelope.signature ||
      !envelope.from ||
      !envelope.nonce ||
      envelope.timestamp == null ||
      envelope.payload == null
    ) {
      return false;
    }

    if (!/^[0-9a-f]{64}$/.test(envelope.senderPublicKey)) return false;
    if (!/^[0-9a-f]{128}$/.test(envelope.signature)) return false;

    const pubBytes = hexToBytes(envelope.senderPublicKey);

    // Verify nodeId ↔ publicKey binding via BLAKE3
    const expectedNodeId = '0x' + bytesToHex(blake3(pubBytes));
    if (expectedNodeId !== envelope.from) {
      return false;
    }

    // Reconstruct the canonical signed message
    const payloadHash = bytesToHex(blake3(new TextEncoder().encode(envelope.payload)));
    const canonical = new TextEncoder().encode(
      `ghostnet:msg:${SIGNATURE_VERSION}:${envelope.nonce}:${envelope.timestamp}:${envelope.from}:${envelope.to ?? ''}:${payloadHash}`,
    );

    if (!verify(hexToBytes(envelope.signature), canonical, pubBytes)) {
      return false;
    }

    // TOFU: register or verify peer key
    const existingKey = this.peerKeys.get(envelope.from);
    if (existingKey) {
      if (bytesToHex(existingKey) !== envelope.senderPublicKey) {
        this.emitSecurity(
          'peer_key_changed',
          `Peer ${envelope.from} message signed with different key — rejecting (TOFU violation)`,
          envelope.from,
        );
        return false;
      }
    } else {
      this.rememberPeer(envelope.from, pubBytes, 'message');
      this.logger.debug(`TOFU: stored key for peer ${envelope.from} from signed message`);
    }

    return true;
  }

  private async handleIncoming(raw: Uint8Array | string): Promise<void> {
    const text = typeof raw === 'string' ? raw : new TextDecoder().decode(raw);

    if (text.length > MAX_MESSAGE_BYTES * 2) {
      this.logger.warn('Incoming message exceeds size limit, dropping');
      return;
    }

    let envelope: {
      type: string;
      from?: string;
      to?: string;
      payload?: string;
      encrypted?: boolean;
      timestamp?: number;
      publicKey?: string;
      nodeId?: string;
      signature?: string;
      senderPublicKey?: string;
      nonce?: string;
      code?: string;
      relayCode?: string;
    };
    try {
      envelope = JSON.parse(text) as typeof envelope;
    } catch {
      this.logger.warn('Received non-JSON message, ignoring');
      return;
    }

    if (!envelope || typeof envelope !== 'object' || typeof envelope.type !== 'string') {
      this.logger.warn('Received invalid envelope structure, ignoring');
      return;
    }

    // ── peer_announce: verify signature before trusting public key ──
    if (
      envelope.type === 'peer_announce' &&
      envelope.nodeId &&
      envelope.publicKey &&
      envelope.signature
    ) {
      const verifiedPub = this.verifyPeerAnnounce(
        envelope.nodeId,
        envelope.publicKey,
        envelope.signature,
      );
      if (verifiedPub) {
        this.rememberPeer(envelope.nodeId, verifiedPub, 'announcement');
        this.logger.debug(`Verified and stored key for peer ${envelope.nodeId}`);
      }
    }

    // ── message: require nonce+timestamp, verify signature, decrypt ──
    if (envelope.type === 'message' && envelope.from && envelope.payload != null) {
      // FIX VULN-02: Require nonce — reject messages without replay protection
      if (!envelope.nonce) {
        this.emitSecurity(
          'missing_nonce',
          `Message from ${envelope.from} has no nonce — dropping`,
          envelope.from,
        );
        return;
      }

      // FIX VULN-02: Require timestamp — reject messages without freshness proof
      if (envelope.timestamp == null) {
        this.emitSecurity(
          'missing_timestamp',
          `Message from ${envelope.from} has no timestamp — dropping`,
          envelope.from,
        );
        return;
      }

      // Timestamp freshness check (cheap, no state mutation — do this first)
      const age = Math.abs(Date.now() - envelope.timestamp);
      if (!Number.isSafeInteger(envelope.timestamp) || age > MESSAGE_MAX_AGE_MS) {
        this.emitSecurity(
          'stale_message',
          `Stale message from ${envelope.from} (age: ${Math.round(age / 1000)}s)`,
          envelope.from,
        );
        return;
      }


      // FIX VULN-04: Verify sender signature — prevents identity spoofing
      if (envelope.signature && envelope.senderPublicKey) {
        if (!this.verifyMessageSignature(envelope)) {
          this.emitSecurity(
            'signature_invalid',
            `Invalid message signature from ${envelope.from} — dropping`,
            envelope.from,
          );
          return;
        }
      } else if (this.requireEncryption) {
        // FIX VULN-04/05: In strict mode, reject unsigned messages
        this.emitSecurity(
          'unsigned_message',
          `Unsigned message from ${envelope.from} — dropping (requireEncryption=true)`,
          envelope.from,
        );
        return;
      }

      if (envelope.to !== this.identity?.nodeId) return;

      if (this.requireEncryption && envelope.encrypted !== true) {
        this.emitSecurity('plaintext_message', `Unencrypted message from ${envelope.from} — dropping`, envelope.from);
        return;
      }

      // FIX VULN-03: Record the nonce LAST — only fresh, authenticated
      // messages consume registry space, so forged/stale traffic can neither
      // pollute the registry nor "burn" a nonce a legitimate sender will use.
      if (!this.checkNonce(envelope.nonce, envelope.timestamp)) {
        this.emitSecurity(
          'replay_detected',
          `Replayed message from ${envelope.from} (nonce: ${envelope.nonce})`,
          envelope.from,
        );
        return;
      }

      let data: string;

      if (envelope.encrypted) {
        try {
          const x25519Priv = edPrivateToX25519(this.identity!.privateKeyBytes);
          const ciphertextBytes = base64ToUint8(envelope.payload);
          data = decrypt(ciphertextBytes, x25519Priv);
        } catch (err) {
          throw err instanceof EncryptionError
            ? err
            : new EncryptionError(`Failed to decrypt payload: ${err instanceof Error ? err.message : String(err)}`);
        }
      } else {
        data = envelope.payload;
      }

      const msg: IncomingMessage = {
        from: envelope.from,
        data,
        timestamp: envelope.timestamp,
      };
      this.emit('message', msg);
    }

    if (envelope.type === 'error') {
      const errPayload = envelope.payload ?? 'Unknown relay error';
      if (errPayload.includes('peer not found') && envelope.from) {
        this.emit('error', new PeerNotFoundError(envelope.from));
      } else {
        const relayCode = envelope.relayCode ?? envelope.code ?? 'ERR_RELAY';
        this.emit('error', new RelayError(errPayload, relayCode));
      }
    }
  }

  /**
   * Emit a security event. Always logs (regardless of debug mode) and
   * always fires the 'security' event so callers can react.
   */
  private emitSecurity(type: string, detail: string, peerId?: string): void {
    console.warn(`[GhostNet:Security] ${detail}`);
    this.emit('security', { type, peerId, detail } as SecurityEvent);
  }

  private emit<K extends keyof GhostNetEvents>(
    event: K,
    ...args: Parameters<GhostNetEvents[K]>
  ): void {
    for (const handler of this.listeners[event]) {
      (handler as (...a: unknown[]) => void)(...args);
    }
  }
}

// ── Helpers ──────────────────────────────────────────────────────────

/** Chunked Uint8Array → base64 (avoids call stack overflow on large arrays). */
function uint8ToBase64(bytes: Uint8Array): string {
  const CHUNK = 8192;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}

/** Base64 → Uint8Array. */
function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
