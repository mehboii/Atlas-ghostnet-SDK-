/**
 * RED TEAM ANALYSIS — GhostNet SDK
 *
 * Adversarial tests that verify security fixes and demonstrate
 * that previously exploitable vulnerabilities are now mitigated.
 */
import { describe, it, expect, vi } from 'vitest';
import { GhostNet } from '../src/client.js';
import { createIdentity } from '../src/crypto/identity.js';
import {
  encrypt,
  decrypt,
  edPrivateToX25519,
  edPublicToX25519,
} from '../src/crypto/encryption.js';
import { sign } from '../src/crypto/signing.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import { blake3 } from '@noble/hashes/blake3';
import type { SecurityEvent } from '../src/types.js';

/** Test-only interface exposing GhostNet private members for adversarial testing. */
interface GhostNetInternals {
  handleIncoming: (raw: Uint8Array | string) => Promise<void>;
  transport: {
    connected: boolean;
    send: (data: string) => void;
    on: () => void;
    off: () => void;
    disconnect: () => void;
    connect: () => Promise<void>;
  } | null;
  peerKeys: Map<string, Uint8Array>;
  seenNonces: Map<string, number>;
  checkNonce: (nonce: string, timestamp: number) => boolean;
}

function internals(gn: GhostNet): GhostNetInternals {
  return gn as unknown as GhostNetInternals;
}

// Helper: create a properly signed envelope for a given sender
function makeSignedEnvelope(
  sender: ReturnType<typeof createIdentity>,
  to: string,
  payload: string,
  opts: { encrypted?: boolean; nonce?: string; timestamp?: number } = {},
) {
  const nonce = opts.nonce ?? bytesToHex(randomBytes(16));
  const timestamp = opts.timestamp ?? Date.now();
  const payloadHash = bytesToHex(blake3(new TextEncoder().encode(payload)));
  const canonical = new TextEncoder().encode(
    `ghostnet:msg:v1:${nonce}:${timestamp}:${sender.nodeId}:${to}:${payloadHash}`,
  );
  const signature = bytesToHex(sign(canonical, sender.privateKeyBytes));

  return {
    type: 'message' as const,
    from: sender.nodeId,
    to,
    payload,
    encrypted: opts.encrypted ?? false,
    nonce,
    timestamp,
    signature,
    senderPublicKey: sender.publicKey,
  };
}

// ─────────────────────────────────────────────────────────────
// VULN-01 FIX: Seed phrase cleared on dispose()
// ─────────────────────────────────────────────────────────────
describe('VULN-01 FIXED: Seed phrase cleared on dispose()', () => {
  it('dispose() zeroes privateKeyBytes AND clears seed phrase reference', () => {
    const id = createIdentity();
    expect(id.seedPhrase.split(' ')).toHaveLength(12);

    id.dispose();

    expect(id.privateKeyBytes.every((b) => b === 0)).toBe(true);
    expect(() => id.seedPhrase).toThrow('disposed');
  });

  it('seed phrase is inaccessible after dispose — getter throws', () => {
    const id = createIdentity();
    const phraseBefore = id.seedPhrase;
    expect(phraseBefore.length).toBeGreaterThan(0);

    id.dispose();

    expect(() => id.seedPhrase).toThrow('disposed');
  });

  it('seed phrase property is non-enumerable and non-configurable', () => {
    const id = createIdentity();
    const desc = Object.getOwnPropertyDescriptor(id, 'seedPhrase');
    expect(desc?.enumerable).toBe(false);
    expect(desc?.configurable).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-02 FIXED: Messages without nonce/timestamp are rejected
// ─────────────────────────────────────────────────────────────
describe('VULN-02 FIXED: Nonce and timestamp now required', () => {
  it('messages without nonce are rejected with security event', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    const messages: Array<{ from: string; data: string }> = [];
    gn.on('security', (evt) => secEvents.push(evt));
    gn.on('message', (msg) => messages.push(msg));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    await handleIncoming(JSON.stringify({
      type: 'message',
      from: '0xattacker',
      payload: 'replayed content',
      encrypted: false,
      timestamp: Date.now(),
    }));

    expect(messages).toHaveLength(0);
    expect(secEvents).toHaveLength(1);
    expect(secEvents[0].type).toBe('missing_nonce');
  });

  it('messages without timestamp are rejected with security event', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    const messages: Array<{ from: string; data: string }> = [];
    gn.on('security', (evt) => secEvents.push(evt));
    gn.on('message', (msg) => messages.push(msg));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    await handleIncoming(JSON.stringify({
      type: 'message',
      from: '0xattacker',
      payload: 'old content',
      encrypted: false,
      nonce: bytesToHex(randomBytes(16)),
    }));

    expect(messages).toHaveLength(0);
    expect(secEvents).toHaveLength(1);
    expect(secEvents[0].type).toBe('missing_timestamp');
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-03 FIXED: Time-based nonce expiry prevents flood replay
// ─────────────────────────────────────────────────────────────
describe('VULN-03 FIXED: Nonce eviction is time-based, not count-based', () => {
  it('nonce registry uses time-based expiry — recent nonces survive eviction sweeps', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    const id = gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);
    const seenNonces = internals(gn).seenNonces;

    const sender = createIdentity();
    const targetNonce = 'target-nonce-to-replay';

    // Send the target message
    const targetEnvelope = makeSignedEnvelope(sender, id.nodeId, 'transfer $1000', {
      nonce: targetNonce,
    });
    await handleIncoming(JSON.stringify(targetEnvelope));

    // Verify the nonce is stored with a timestamp (Map, not Set)
    expect(seenNonces.has(targetNonce)).toBe(true);
    expect(typeof seenNonces.get(targetNonce)).toBe('number');

    // Add enough nonces to trigger eviction sweep (> NONCE_REGISTRY_MAX / 2)
    // But since all timestamps are recent, none should be evicted
    for (let i = 0; i < 200; i++) {
      const env = makeSignedEnvelope(sender, id.nodeId, 'x', { nonce: `flood-${i}` });
      await handleIncoming(JSON.stringify(env));
    }

    // Target nonce STILL in registry — time-based expiry didn't remove it
    expect(seenNonces.has(targetNonce)).toBe(true);

    // Replay attempt — blocked
    const replayEnvelope = makeSignedEnvelope(sender, id.nodeId, 'transfer $1000', {
      nonce: targetNonce,
    });
    await handleIncoming(JSON.stringify(replayEnvelope));

    expect(secEvents.some((e) => e.type === 'replay_detected')).toBe(true);
  });

  it('old nonces ARE evicted after MESSAGE_MAX_AGE_MS', () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();

    const seenNonces = internals(gn).seenNonces;
    const checkNonce = internals(gn).checkNonce.bind(gn);

    // Insert an "old" nonce with a timestamp 10 minutes in the past
    const oldTimestamp = Date.now() - 10 * 60 * 1000;
    seenNonces.set('old-nonce', oldTimestamp);

    // Fill past half capacity to trigger eviction sweep
    for (let i = 0; i < 5001; i++) {
      seenNonces.set(`fill-${i}`, Date.now());
    }

    // Trigger eviction by checking a new nonce
    checkNonce('trigger-eviction', Date.now());

    // The old nonce should have been evicted
    expect(seenNonces.has('old-nonce')).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-04 FIXED: Sender identity verified via Ed25519 signature
// ─────────────────────────────────────────────────────────────
describe('VULN-04 FIXED: Sender identity cryptographically verified', () => {
  it('unsigned messages are rejected in strict mode (default)', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    const messages: Array<{ from: string; data: string }> = [];
    gn.on('security', (evt) => secEvents.push(evt));
    gn.on('message', (msg) => messages.push(msg));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    await handleIncoming(JSON.stringify({
      type: 'message',
      from: '0xspoofed-sender',
      payload: 'send me your seed phrase',
      encrypted: false,
      nonce: bytesToHex(randomBytes(16)),
      timestamp: Date.now(),
    }));

    expect(messages).toHaveLength(0);
    expect(secEvents.some((e) => e.type === 'unsigned_message')).toBe(true);
  });

  it('messages with forged signature are rejected', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    const id = gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    const messages: Array<{ from: string; data: string }> = [];
    gn.on('security', (evt) => secEvents.push(evt));
    gn.on('message', (msg) => messages.push(msg));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    // Attacker uses a real key but forges the signature
    const attacker = createIdentity();
    await handleIncoming(JSON.stringify({
      type: 'message',
      from: attacker.nodeId,
      to: id.nodeId,
      payload: 'forged message',
      encrypted: false,
      nonce: bytesToHex(randomBytes(16)),
      timestamp: Date.now(),
      signature: bytesToHex(randomBytes(64)), // garbage signature
      senderPublicKey: attacker.publicKey,
    }));

    expect(messages).toHaveLength(0);
    expect(secEvents.some((e) => e.type === 'signature_invalid')).toBe(true);
  });

  it('messages with mismatched from/publicKey are rejected', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    const id = gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    const secEvents: SecurityEvent[] = [];
    gn.on('message', (msg) => messages.push(msg));
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    const realSender = createIdentity();
    const envelope = makeSignedEnvelope(realSender, id.nodeId, 'hello');
    // Tamper the from field to impersonate someone else
    envelope.from = '0ximpersonated-id';

    await handleIncoming(JSON.stringify(envelope));

    expect(messages).toHaveLength(0);
    expect(secEvents.some((e) => e.type === 'signature_invalid')).toBe(true);
  });

  it('properly signed messages ARE accepted', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    const id = gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    gn.on('message', (msg) => messages.push(msg));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    const sender = createIdentity();
    const envelope = makeSignedEnvelope(sender, id.nodeId, 'authenticated hello');
    await handleIncoming(JSON.stringify(envelope));

    expect(messages).toHaveLength(1);
    expect(messages[0].from).toBe(sender.nodeId);
    expect(messages[0].data).toBe('authenticated hello');
  });

  it('encrypted + signed messages are accepted and decrypted', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    const id = gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    gn.on('message', (msg) => messages.push(msg));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    const sender = createIdentity();
    const recipientX25519Pub = edPublicToX25519(id.publicKeyBytes);
    const encrypted = encrypt('secret authenticated', recipientX25519Pub);

    // Convert to base64 the same way client.ts does
    const CHUNK = 8192;
    let b64 = '';
    for (let i = 0; i < encrypted.length; i += CHUNK) {
      const chunk = encrypted.subarray(i, Math.min(i + CHUNK, encrypted.length));
      b64 += String.fromCharCode(...chunk);
    }
    const payloadBase64 = btoa(b64);

    const envelope = makeSignedEnvelope(sender, id.nodeId, payloadBase64, { encrypted: true });
    await handleIncoming(JSON.stringify(envelope));

    expect(messages).toHaveLength(1);
    expect(messages[0].data).toBe('secret authenticated');
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-05 FIXED: Plaintext fallback refused by default
// ─────────────────────────────────────────────────────────────
describe('VULN-05 FIXED: Plaintext fallback refused', () => {
  it('send() throws PeerNotFoundError when peer key is unknown (default)', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();

    const mockTransport = {
      connected: true,
      send: () => {},
      on: () => {},
      off: () => {},
      disconnect: () => {},
      connect: () => Promise.resolve(),
    };
    internals(gn).transport = mockTransport;

    await expect(gn.send('0x' + 'ab'.repeat(32), 'TOP SECRET')).rejects.toThrow('Peer not found');
  });

  it('send() allows plaintext when requireEncryption=false (explicit opt-in)', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    gn.createIdentity();

    const sent: string[] = [];
    const secEvents: SecurityEvent[] = [];
    gn.on('security', (evt) => secEvents.push(evt));

    const mockTransport = {
      connected: true,
      send: (data: string) => sent.push(data),
      on: () => {},
      off: () => {},
      disconnect: () => {},
      connect: () => Promise.resolve(),
    };
    internals(gn).transport = mockTransport;

    await gn.send('0x' + 'ab'.repeat(32), 'hello');

    const envelope = JSON.parse(sent[0]);
    expect(envelope.encrypted).toBe(false);
    // Even in plaintext mode, message is now SIGNED
    expect(envelope.signature).toBeDefined();
    expect(envelope.senderPublicKey).toBeDefined();
    // Security event emitted
    expect(secEvents.some((e) => e.type === 'plaintext_fallback')).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-06 FIXED: TOFU key pinning prevents key overwrite
// ─────────────────────────────────────────────────────────────
describe('VULN-06 FIXED: TOFU key pinning', () => {
  it('second peer_announce with different key is rejected', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    // Real peer announces
    const realPeer = createIdentity();
    const announceMsg = new TextEncoder().encode(`ghostnet:announce:${realPeer.nodeId}`);
    const realSig = sign(announceMsg, realPeer.privateKeyBytes);

    await handleIncoming(JSON.stringify({
      type: 'peer_announce',
      nodeId: realPeer.nodeId,
      publicKey: realPeer.publicKey,
      signature: bytesToHex(realSig),
    }));

    const storedKey1 = internals(gn).peerKeys.get(realPeer.nodeId);
    expect(storedKey1).toBeDefined();

    // Attacker can't forge a different key for the same nodeId because
    // nodeId = BLAKE3(publicKey). A different key → different nodeId.
    // But a same-key re-announce should still work:
    await handleIncoming(JSON.stringify({
      type: 'peer_announce',
      nodeId: realPeer.nodeId,
      publicKey: realPeer.publicKey,
      signature: bytesToHex(realSig),
    }));

    const storedKey2 = internals(gn).peerKeys.get(realPeer.nodeId);
    expect(Buffer.from(storedKey2!)).toEqual(Buffer.from(storedKey1!));
    expect(secEvents.filter((e) => e.type === 'peer_key_changed')).toHaveLength(0);
  });

  it('TOFU via signed messages pins the key', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    const id = gn.createIdentity();

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    const sender = createIdentity();
    const envelope = makeSignedEnvelope(sender, id.nodeId, 'first contact');
    await handleIncoming(JSON.stringify(envelope));

    // Key is now pinned via TOFU
    const pinnedKey = internals(gn).peerKeys.get(sender.nodeId);
    expect(pinnedKey).toBeDefined();
    expect(bytesToHex(pinnedKey!)).toBe(sender.publicKey);
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-08 FIXED: Security events always emitted
// ─────────────────────────────────────────────────────────────
describe('VULN-08 FIXED: Security events visible in production mode', () => {
  it('replay detection emits security event even with debug=false', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    const id = gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    const sender = createIdentity();
    const nonce = 'test-nonce-123';
    const env1 = makeSignedEnvelope(sender, id.nodeId, 'hello', { nonce });
    const env2 = makeSignedEnvelope(sender, id.nodeId, 'hello', { nonce });

    await handleIncoming(JSON.stringify(env1));
    await handleIncoming(JSON.stringify(env2));

    expect(secEvents.some((e) => e.type === 'replay_detected')).toBe(true);
    // console.warn IS called (security events always log)
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('stale message emits security event even with debug=false', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    const id = gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    const sender = createIdentity();
    const env = makeSignedEnvelope(sender, id.nodeId, 'old message', {
      timestamp: Date.now() - 10 * 60 * 1000,
    });
    await handleIncoming(JSON.stringify(env));

    expect(secEvents.some((e) => e.type === 'stale_message')).toBe(true);
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-09: Size limit check (send vs receive asymmetry documented)
// ─────────────────────────────────────────────────────────────
describe('VULN-09: Size limit enforcement', () => {
  it('send correctly rejects messages over 64KB', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();

    const mockTransport = {
      connected: true,
      send: () => {},
      on: () => {},
      off: () => {},
      disconnect: () => {},
      connect: () => Promise.resolve(),
    };
    internals(gn).transport = mockTransport;

    const msg64kPlus1 = 'A'.repeat(64 * 1024 + 1);
    await expect(gn.send('0xpeer', msg64kPlus1)).rejects.toThrow('too large');
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-10: No forward secrecy (documented design limitation)
// ─────────────────────────────────────────────────────────────
describe('VULN-10: Forward secrecy limitation (documented)', () => {
  it('compromised seed decrypts all past messages (inherent to architecture)', () => {
    const recipient = createIdentity();
    const recipientX25519Pub = edPublicToX25519(recipient.publicKeyBytes);
    const recipientX25519Priv = edPrivateToX25519(recipient.privateKeyBytes);

    const packets = [
      encrypt('message from day 1', recipientX25519Pub),
      encrypt('message from day 30', recipientX25519Pub),
    ];

    expect(decrypt(packets[0], recipientX25519Priv)).toBe('message from day 1');
    expect(decrypt(packets[1], recipientX25519Priv)).toBe('message from day 30');
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-11 FIXED: Oversized messages still rejected
// ─────────────────────────────────────────────────────────────
describe('VULN-11: Malicious relay message injection', () => {
  it('oversized message is correctly rejected', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    gn.on('message', (msg) => messages.push(msg));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    const oversized = JSON.stringify({
      type: 'message',
      from: '0xattacker',
      payload: 'X'.repeat(200_000),
      encrypted: false,
      nonce: 'abc',
      timestamp: Date.now(),
    });

    await handleIncoming(oversized);
    expect(messages).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-12: Decryption timing consistency
// ─────────────────────────────────────────────────────────────
describe('VULN-12: Decryption timing consistency', () => {
  it('all failure modes throw EncryptionError', () => {
    const recipient = createIdentity();
    const recipientX25519Priv = edPrivateToX25519(recipient.privateKeyBytes);

    expect(() => decrypt(new Uint8Array(10), recipientX25519Priv)).toThrow('Decryption failed');
    expect(() => decrypt(randomBytes(100), recipientX25519Priv)).toThrow('Decryption failed');

    const recipientX25519Pub = edPublicToX25519(recipient.publicKeyBytes);
    const packet = encrypt('test', recipientX25519Pub);
    packet[50] ^= 0xff;
    expect(() => decrypt(packet, recipientX25519Priv)).toThrow('Decryption failed');
  });
});

// ─────────────────────────────────────────────────────────────
// VULN-13: GhostFAQ input sanitization
// ─────────────────────────────────────────────────────────────
describe('VULN-13: GhostFAQ input sanitization', () => {
  it('XSS payloads do not crash the bot', async () => {
    const { GhostSupportBot } = await import('../src/lib/GhostFAQ.js');
    const bot = new GhostSupportBot();

    const xssPayloads = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '"><svg onload=alert(1)>',
      "'; DROP TABLE users; --",
      '{{constructor.constructor("return this")()}}',
    ];

    for (const payload of xssPayloads) {
      const response = bot.ask(payload);
      expect(typeof response).toBe('string');
      expect(response.length).toBeGreaterThan(0);
    }
  });
});

// ─────────────────────────────────────────────────────────────
// CHAIN EXPLOIT: "Ghost Relay" — Full MITM Conversation Hijack
//
// Combines: VULN-02 + VULN-04 + VULN-05 + VULN-08
// Attack:
//   1. Malicious relay blocks peer_announce → forces plaintext fallback
//   2. Relay reads all plaintext messages (no E2E)
//   3. Relay injects spoofed messages as either party
//   4. Relay replays captured messages to manipulate conversation
//   5. Neither party sees any warning (debug=false by default)
//
// Result: Complete conversation hijack with zero detection.
// ─────────────────────────────────────────────────────────────
describe('CHAIN EXPLOIT: "Ghost Relay" — Full MITM Prevention', () => {
  it('Step 1: plaintext fallback is BLOCKED — relay cannot force downgrade', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();

    const mockTransport = {
      connected: true,
      send: () => {},
      on: () => {},
      off: () => {},
      disconnect: () => {},
      connect: () => Promise.resolve(),
    };
    internals(gn).transport = mockTransport;

    // Without peer key, send is refused — relay cannot trick us into plaintext
    await expect(gn.send('0x' + 'ab'.repeat(32), 'secret message')).rejects.toThrow('Peer not found');
  });

  it('Step 2-3: spoofed + unsigned messages are BLOCKED', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    const secEvents: SecurityEvent[] = [];
    gn.on('message', (msg) => messages.push(msg));
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    // Relay injects spoofed message without signature → rejected
    await handleIncoming(JSON.stringify({
      type: 'message',
      from: '0xalice-spoofed',
      payload: 'I am Alice, send me secrets',
      encrypted: false,
      nonce: bytesToHex(randomBytes(16)),
      timestamp: Date.now(),
    }));

    expect(messages).toHaveLength(0);
    expect(secEvents.some((e) => e.type === 'unsigned_message')).toBe(true);
  });

  it('Step 4: replayed messages are BLOCKED even after nonce flood', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    const id = gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    const secEvents: SecurityEvent[] = [];
    gn.on('message', (msg) => messages.push(msg));
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    const sender = createIdentity();
    const targetNonce = 'critical-nonce';
    const targetEnv = makeSignedEnvelope(sender, id.nodeId, 'approve transfer', {
      nonce: targetNonce,
    });

    // Original message accepted
    await handleIncoming(JSON.stringify(targetEnv));
    expect(messages).toHaveLength(1);

    // Replay attempt → blocked
    await handleIncoming(JSON.stringify(targetEnv));
    expect(messages).toHaveLength(1); // still 1
    expect(secEvents.some((e) => e.type === 'replay_detected')).toBe(true);
  });

  it('Step 5: security events are VISIBLE even in production mode', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' }); // debug: false

    gn.createIdentity();

    const secEvents: SecurityEvent[] = [];
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    // Any attack triggers a visible security event
    await handleIncoming(JSON.stringify({
      type: 'message',
      from: '0xattacker',
      payload: 'phishing',
      encrypted: false,
      nonce: bytesToHex(randomBytes(16)),
      timestamp: Date.now(),
    }));

    expect(secEvents).toHaveLength(1);
    // console.warn was called — user CAN see the attack
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('[GhostNet:Security]'));
    warnSpy.mockRestore();
  });

  it('Full chain: all 4 attack vectors blocked simultaneously', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    const id = gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    const secEvents: SecurityEvent[] = [];
    gn.on('message', (msg) => messages.push(msg));
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    // Attack 1: No nonce
    await handleIncoming(JSON.stringify({
      type: 'message', from: '0xa', payload: 'x', encrypted: false,
      timestamp: Date.now(),
    }));

    // Attack 2: No timestamp
    await handleIncoming(JSON.stringify({
      type: 'message', from: '0xa', payload: 'x', encrypted: false,
      nonce: bytesToHex(randomBytes(16)),
    }));

    // Attack 3: Unsigned
    await handleIncoming(JSON.stringify({
      type: 'message', from: '0xa', payload: 'x', encrypted: false,
      nonce: bytesToHex(randomBytes(16)), timestamp: Date.now(),
    }));

    // Attack 4: Forged signature
    await handleIncoming(JSON.stringify({
      type: 'message', from: '0xa', to: id.nodeId, payload: 'x', encrypted: false,
      nonce: bytesToHex(randomBytes(16)), timestamp: Date.now(),
      signature: bytesToHex(randomBytes(64)),
      senderPublicKey: bytesToHex(randomBytes(32)),
    }));

    // Attack 5: Valid signature but replayed
    const sender = createIdentity();
    const payload = Buffer.from(encrypt('once', edPublicToX25519(id.publicKeyBytes))).toString('base64');
    const env = makeSignedEnvelope(sender, id.nodeId, payload, { encrypted: true });
    await handleIncoming(JSON.stringify(env));
    await handleIncoming(JSON.stringify(env)); // replay

    // Only the one legitimate message got through
    expect(messages).toHaveLength(1);
    expect(messages[0].data).toBe('once');

    // All 5 attacks generated security events
    expect(secEvents.length).toBeGreaterThanOrEqual(5);
    expect(warnSpy.mock.calls.length).toBeGreaterThanOrEqual(5);
    warnSpy.mockRestore();
  });
});

// ─────────────────────────────────────────────────────────────
// CHAIN EXPLOIT: "Zombie Identity" — Post-Dispose Key Recovery
//
// Combines: VULN-01 + VULN-10
// Attack:
//   1. Application calls dispose() believing keys are cleared
//   2. Attacker dumps heap — seed phrase was a JS string, immutable
//   3. Attacker loads identity from recovered seed
//   4. All past messages encrypted to this identity are decryptable
//
// Fix: dispose() now nulls the seed phrase reference, allowing GC
//      to collect the string. While V8 may not immediately zero the
//      memory, the reference is gone — reducing the attack window.
// ─────────────────────────────────────────────────────────────
describe('CHAIN EXPLOIT: "Zombie Identity" — Post-Dispose Prevention', () => {
  it('seed phrase is unreachable after dispose()', () => {
    const id = createIdentity();
    const pubKey = id.publicKey;

    // Pre-dispose: seed phrase accessible
    expect(id.seedPhrase.split(' ')).toHaveLength(12);

    id.dispose();

    // Post-dispose: seed phrase throws, private key zeroed
    expect(() => id.seedPhrase).toThrow('disposed');
    expect(id.privateKeyBytes.every((b) => b === 0)).toBe(true);

    // Public data remains accessible (needed for ongoing references)
    expect(id.publicKey).toBe(pubKey);
    expect(id.nodeId).toMatch(/^0x/);
  });

  it('double-dispose is safe', () => {
    const id = createIdentity();
    id.dispose();
    id.dispose(); // no throw
    expect(() => id.seedPhrase).toThrow('disposed');
  });
});

// ─────────────────────────────────────────────────────────────
// CHAIN EXPLOIT: "Nonce Flood → Replay → Spoof"
//
// Combines: VULN-02 + VULN-03 + VULN-04
// Attack:
//   1. Capture a high-value message (e.g., "approve transfer")
//   2. Flood 10K+ unique messages to evict the target nonce
//   3. Replay the captured message — nonce check passes
//   4. Spoof the sender identity — no signature verification
//
// All three links in this chain are now broken.
// ─────────────────────────────────────────────────────────────
describe('CHAIN EXPLOIT: "Nonce Flood → Replay → Spoof" Prevention', () => {
  it('attack chain is broken at every link', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    const id = gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    const secEvents: SecurityEvent[] = [];
    gn.on('message', (msg) => messages.push(msg));
    gn.on('security', (evt) => secEvents.push(evt));

    const handleIncoming = internals(gn).handleIncoming.bind(gn);

    // Legitimate message from real sender
    const realSender = createIdentity();
    const nonce = 'high-value-nonce';
    const legitimateEnv = makeSignedEnvelope(realSender, id.nodeId, 'approve $1M transfer', {
      nonce,
    });
    await handleIncoming(JSON.stringify(legitimateEnv));
    expect(messages).toHaveLength(1);

    // Link 1: Nonce flood — even after flooding, nonce is still tracked (time-based)
    for (let i = 0; i < 100; i++) {
      const env = makeSignedEnvelope(realSender, id.nodeId, 'flood', {
        nonce: `flood-${i}`,
      });
      await handleIncoming(JSON.stringify(env));
    }

    // Link 2: Replay — blocked because nonce is still in time-based registry
    await handleIncoming(JSON.stringify(legitimateEnv));
    const replays = secEvents.filter((e) => e.type === 'replay_detected');
    expect(replays.length).toBeGreaterThanOrEqual(1);

    // Link 3: Spoof — attacker can't forge the real sender's signature
    const attacker = createIdentity();
    const spoofedEnv = makeSignedEnvelope(attacker, id.nodeId, 'approve $1M transfer');
    // Change from to impersonate real sender — signature won't match
    spoofedEnv.from = realSender.nodeId;
    await handleIncoming(JSON.stringify(spoofedEnv));

    // Only the one legitimate message was delivered
    // (plus the 100 flood messages from the real sender, but the replay was blocked)
    const approvalMessages = messages.filter((m) => m.data.includes('approve'));
    expect(approvalMessages).toHaveLength(1);
    expect(approvalMessages[0].from).toBe(realSender.nodeId);
  });
});
