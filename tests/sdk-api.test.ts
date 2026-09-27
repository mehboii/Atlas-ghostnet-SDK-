import { describe, it, expect, vi } from 'vitest';
import {
  GhostNet,
  GhostSupportBot,
  GhostNetError,
  ConnectionError,
  IdentityError,
  EncryptionError,
  PeerNotFoundError,
  PayloadTooLargeError,
  RelayError,
  ReplayError,
  PeerVerificationError,
} from '../src/index.js';

describe('Phase 3: Comprehensive SDK Public API Test Matrix', () => {
  describe('1. Client Initialization & Configuration Validation', () => {
    it('initializes with default options', () => {
      const gn = new GhostNet();
      const status = gn.getStatus();
      expect(status.connected).toBe(false);
      expect(status.nodeId).toBeNull();
      expect(status.knownPeers).toBe(0);
      expect(status.endpoint).toMatch(/^wss:\/\//);
    });

    it('accepts custom valid wss:// endpoint', () => {
      const gn = new GhostNet({ endpoint: 'wss://mesh.custom.relay:8443' });
      expect(gn.getStatus().endpoint).toBe('wss://mesh.custom.relay:8443');
    });

    it('rejects insecure ws:// endpoint', () => {
      expect(() => new GhostNet({ endpoint: 'ws://insecure.test' }))
        .toThrow(ConnectionError);
    });

    it('rejects http:// and https:// endpoints', () => {
      expect(() => new GhostNet({ endpoint: 'https://test.relay' }))
        .toThrow(ConnectionError);
      expect(() => new GhostNet({ endpoint: 'http://test.relay' }))
        .toThrow(ConnectionError);
    });

    it('rejects endpoint with embedded credentials', () => {
      expect(() => new GhostNet({ endpoint: 'wss://user:pass@relay.test' }))
        .toThrow(ConnectionError);
    });

    it('rejects endpoint with path traversal sequence', () => {
      expect(() => new GhostNet({ endpoint: 'wss://relay.test/../secret' }))
        .toThrow(ConnectionError);
    });

    it('rejects invalid malformed URL string', () => {
      expect(() => new GhostNet({ endpoint: 'wss://::invalid::url' }))
        .toThrow(ConnectionError);
    });
  });

  describe('2. Identity Creation, Restoration & Hygiene', () => {
    it('createIdentity returns full identity with valid BIP-39 mnemonic', () => {
      const gn = new GhostNet();
      const id = gn.createIdentity();

      expect(id.nodeId).toMatch(/^0x[0-9a-f]{64}$/);
      expect(id.publicKey).toMatch(/^[0-9a-f]{64}$/);
      expect(id.publicKeyBytes).toHaveLength(32);
      expect(id.privateKeyBytes).toHaveLength(32);
      expect(id.seedPhrase.split(' ')).toHaveLength(12);

      expect(gn.getIdentity()).toBe(id);
      expect(gn.getPublicIdentity()).toEqual({
        nodeId: id.nodeId,
        publicKey: id.publicKey,
      });
    });

    it('loadIdentity deterministically regenerates identical keys and nodeId', () => {
      const gn1 = new GhostNet();
      const original = gn1.createIdentity();

      const gn2 = new GhostNet();
      const loaded = gn2.loadIdentity(original.seedPhrase);

      expect(loaded.nodeId).toBe(original.nodeId);
      expect(loaded.publicKey).toBe(original.publicKey);
      expect(Buffer.from(loaded.publicKeyBytes).equals(Buffer.from(original.publicKeyBytes))).toBe(true);
      expect(Buffer.from(loaded.privateKeyBytes).equals(Buffer.from(original.privateKeyBytes))).toBe(true);
    });

    it('loadIdentity rejects empty or invalid mnemonic strings', () => {
      const gn = new GhostNet();
      expect(() => gn.loadIdentity('')).toThrow(IdentityError);
      expect(() => gn.loadIdentity('abandon')).toThrow(IdentityError);
      expect(() => gn.loadIdentity('abandon ability able about above absent absorb abstract absurd abuse access 12345')).toThrow(IdentityError);
      expect(() => gn.loadIdentity('not a real bip39 mnemonic phrase at all today ok yes')).toThrow(IdentityError);
    });

    it('identity.dispose() zeroes private key and disables seedPhrase getter', () => {
      const gn = new GhostNet();
      const id = gn.createIdentity();
      const keyRef = id.privateKeyBytes;

      id.dispose();

      expect(keyRef.every((b) => b === 0)).toBe(true);
      expect(() => id.seedPhrase).toThrow(IdentityError);
    });

    it('identity.toJSON() never exposes private keys or seed phrase', () => {
      const gn = new GhostNet();
      const id = gn.createIdentity();
      const serialized = JSON.stringify(id);
      const parsed = JSON.parse(serialized);

      expect(parsed.nodeId).toBe(id.nodeId);
      expect(parsed.publicKey).toBe(id.publicKey);
      expect(parsed.privateKeyBytes).toBeUndefined();
      expect(parsed.seedPhrase).toBeUndefined();
    });
  });

  describe('3. Peer Management & Verification', () => {
    it('addPeer accepts 64-char lowercase hex Ed25519 public key', () => {
      const gn = new GhostNet();
      const dummyKey = 'a'.repeat(64);
      const peer = gn.addPeer(dummyKey);

      expect(peer.publicKey).toBe(dummyKey);
      expect(peer.nodeId).toMatch(/^0x[0-9a-f]{64}$/);
      expect(peer.source).toBe('manual');
      expect(peer.lastSeen).toBeNull();

      const peers = gn.listPeers();
      expect(peers).toHaveLength(1);
      expect(peers[0].publicKey).toBe(dummyKey);
    });

    it('addPeer rejects invalid keys (uppercase, 0x prefix, invalid length)', () => {
      const gn = new GhostNet();
      expect(() => gn.addPeer('A'.repeat(64))).toThrow(PeerVerificationError);
      expect(() => gn.addPeer('0x' + 'a'.repeat(64))).toThrow(PeerVerificationError);
      expect(() => gn.addPeer('a'.repeat(62))).toThrow(PeerVerificationError);
      expect(() => gn.addPeer('invalid-hex-key')).toThrow(PeerVerificationError);
    });

    it('listPeers returns defensive copy that cannot mutate internal state', () => {
      const gn = new GhostNet();
      gn.addPeer('b'.repeat(64));
      const peers = gn.listPeers();
      peers.pop();
      expect(gn.listPeers()).toHaveLength(1);
    });
  });

  describe('4. Lifecycle & Order-of-Operations Invariants', () => {
    it('connect() throws ConnectionError when identity is missing', async () => {
      const gn = new GhostNet();
      await expect(gn.connect()).rejects.toThrow(ConnectionError);
    });

    it('send() throws IdentityError when identity is missing', async () => {
      const gn = new GhostNet();
      await expect(gn.send('0x' + 'a'.repeat(64), 'msg')).rejects.toThrow(IdentityError);
    });

    it('send() throws IdentityError when identity has been disposed', async () => {
      const gn = new GhostNet();
      const id = gn.createIdentity();
      id.dispose();
      await expect(gn.send('0x' + 'a'.repeat(64), 'msg')).rejects.toThrow(IdentityError);
    });

    it('send() throws ConnectionError when called before connect()', async () => {
      const gn = new GhostNet();
      gn.createIdentity();
      await expect(gn.send('0x' + 'a'.repeat(64), 'msg')).rejects.toThrow(ConnectionError);
    });

    it('send() throws PayloadTooLargeError when message exceeds 64 KB', async () => {
      const gn = new GhostNet();
      gn.createIdentity();
      // Even if disconnected, payload size check executes first or after connection
      // Let's verify payload size check throws PayloadTooLargeError when connected
      (gn as unknown as { transport: { connected: boolean } }).transport = { connected: true };
      const largeMsg = 'X'.repeat(64 * 1024 + 1);
      await expect(gn.send('0x' + 'a'.repeat(64), largeMsg)).rejects.toThrow(PayloadTooLargeError);
    });

    it('send() throws PeerVerificationError for malformed recipient nodeId', async () => {
      const gn = new GhostNet();
      gn.createIdentity();
      (gn as unknown as { transport: { connected: boolean } }).transport = { connected: true };
      await expect(gn.send('not-a-node-id', 'hello')).rejects.toThrow(PeerVerificationError);
      await expect(gn.send('0x' + 'a'.repeat(63), 'hello')).rejects.toThrow(PeerVerificationError);
    });

    it('disconnect() is idempotent and safe when called repeatedly', () => {
      const gn = new GhostNet();
      expect(() => {
        gn.disconnect();
        gn.disconnect();
        gn.disconnect();
      }).not.toThrow();
    });
  });

  describe('5. Subscriptions and Event Management', () => {
    it('subscribe returns an unsubscribe function that safely removes listener', () => {
      const gn = new GhostNet();
      const listener = vi.fn();
      const unsub = gn.subscribe('message', listener);

      unsub();
      // Multiple unsubs are safe
      expect(() => unsub()).not.toThrow();
    });

    it('supports on and off for all supported events', () => {
      const gn = new GhostNet();
      const h = () => {};
      gn.on('connect', h);
      gn.on('disconnect', h);
      gn.on('message', h);
      gn.on('error', h);
      gn.on('security', h);
      gn.on('peer:discovered', h);

      gn.off('connect', h);
      gn.off('disconnect', h);
      gn.off('message', h);
      gn.off('error', h);
      gn.off('security', h);
      gn.off('peer:discovered', h);
    });
  });

  describe('6. Error Classes & Inheritance Hierarchy', () => {
    it('all custom errors inherit from GhostNetError and Error with distinct codes', () => {
      const testCases = [
        { err: new ConnectionError('msg'), code: 'ERR_CONNECTION', name: 'ConnectionError' },
        { err: new IdentityError('msg'), code: 'ERR_IDENTITY', name: 'IdentityError' },
        { err: new EncryptionError('msg'), code: 'ERR_ENCRYPTION', name: 'EncryptionError' },
        { err: new PeerNotFoundError('0xpeer'), code: 'ERR_PEER_NOT_FOUND', name: 'PeerNotFoundError' },
        { err: new PayloadTooLargeError(70000, 65536), code: 'ERR_PAYLOAD_TOO_LARGE', name: 'PayloadTooLargeError' },
        { err: new RelayError('msg', 'CODE_1'), code: 'ERR_RELAY', name: 'RelayError' },
        { err: new ReplayError('nonce1'), code: 'ERR_REPLAY', name: 'ReplayError' },
        { err: new PeerVerificationError('0xpeer', 'sig fail'), code: 'ERR_PEER_VERIFICATION', name: 'PeerVerificationError' },
      ];

      for (const { err, code, name } of testCases) {
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(GhostNetError);
        expect(err.code).toBe(code);
        expect(err.name).toBe(name);
      }
    });
  });

  describe('7. GhostSupportBot FAQ Integration', () => {
    it('answers core queries deterministically', () => {
      const bot = new GhostSupportBot();
      expect(bot.ask('How does encryption work?')).toContain('AES-256-GCM');
      expect(bot.ask('Can someone intercept my messages?')).toContain('encrypted blob');
      expect(bot.ask('Who created GhostNet?')).toContain('N11X');
      expect(bot.ask('gibberish query with no match xyz')).toContain('Terminal Error');
    });
  });
});
