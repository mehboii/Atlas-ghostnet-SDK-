/**
 * Integration tests for @n11x/atlas
 *
 * These tests exercise the SDK's public API surface as an external developer would use it.
 * They cover identity creation/restoration, connection lifecycle, messaging, and error cases.
 *
 * Note: Tests that require a live relay connection are skipped by default.
 * Set GHOSTNET_RELAY_URL env var to run them against a real relay.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  GhostNet,
  GhostNetError,
  ConnectionError,
  IdentityError,
  EncryptionError,
  PeerNotFoundError,
} from '../../src/index.js';

// ── Identity Tests ─────────────────────────────────────────────────

describe('Identity — create', () => {
  it('creates an identity with nodeId and seedPhrase', () => {
    const gn = new GhostNet();
    const id = gn.createIdentity();

    expect(id.nodeId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(id.seedPhrase).toBeDefined();
    expect(id.seedPhrase.split(' ')).toHaveLength(12);
    expect(id.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(id.publicKeyBytes).toBeInstanceOf(Uint8Array);
    expect(id.publicKeyBytes).toHaveLength(32);
    expect(id.privateKeyBytes).toBeInstanceOf(Uint8Array);
    expect(id.privateKeyBytes).toHaveLength(32);
  });

  it('creates unique identities each time', () => {
    const gn = new GhostNet();
    const id1 = gn.createIdentity();
    const id2 = gn.createIdentity();

    expect(id1.nodeId).not.toBe(id2.nodeId);
    expect(id1.seedPhrase).not.toBe(id2.seedPhrase);
  });

  it('identity.dispose() zeroes private key material', () => {
    const gn = new GhostNet();
    const id = gn.createIdentity();
    const privKeyRef = id.privateKeyBytes;

    id.dispose();

    // All bytes should be zero after dispose
    expect(privKeyRef.every((b) => b === 0)).toBe(true);
  });

  it('identity does not leak secrets via JSON.stringify', () => {
    const gn = new GhostNet();
    const id = gn.createIdentity();
    const json = JSON.stringify(id);
    const parsed = JSON.parse(json);

    expect(parsed).toHaveProperty('publicKey');
    expect(parsed).toHaveProperty('nodeId');
    expect(parsed).not.toHaveProperty('seedPhrase');
    expect(parsed).not.toHaveProperty('privateKeyBytes');
  });
});

describe('Identity — restore from seed phrase', () => {
  it('restores the same nodeId from the same seed phrase', () => {
    const gn1 = new GhostNet();
    const original = gn1.createIdentity();
    const seedPhrase = original.seedPhrase;

    const gn2 = new GhostNet();
    const restored = gn2.loadIdentity(seedPhrase);

    expect(restored.nodeId).toBe(original.nodeId);
    expect(restored.publicKey).toBe(original.publicKey);
  });

  it('throws IdentityError for invalid seed phrase', () => {
    const gn = new GhostNet();
    expect(() => gn.loadIdentity('not a valid seed phrase at all')).toThrow(IdentityError);
  });

  it('throws IdentityError for empty string', () => {
    const gn = new GhostNet();
    expect(() => gn.loadIdentity('')).toThrow(IdentityError);
  });

  it('throws IdentityError for partial seed phrase', () => {
    const gn = new GhostNet();
    expect(() => gn.loadIdentity('abandon ability able')).toThrow(IdentityError);
  });
});

// ── Connection Tests ───────────────────────────────────────────────

describe('Connection', () => {
  it('throws ConnectionError when connecting without identity', async () => {
    const gn = new GhostNet();
    await expect(gn.connect()).rejects.toThrow(ConnectionError);
  });

  it('rejects insecure ws:// endpoint', () => {
    expect(() => new GhostNet({ endpoint: 'ws://insecure.example.com' })).toThrow(ConnectionError);
  });

  it('rejects http:// endpoint', () => {
    expect(() => new GhostNet({ endpoint: 'http://evil.com' })).toThrow(ConnectionError);
  });

  it('rejects endpoint with embedded credentials', () => {
    expect(() => new GhostNet({ endpoint: 'wss://user:pass@evil.com' })).toThrow(ConnectionError);
  });

  it('rejects endpoint with path traversal', () => {
    expect(() => new GhostNet({ endpoint: 'wss://evil.com/../../etc/passwd' })).toThrow(ConnectionError);
  });

  it('accepts valid wss:// endpoint', () => {
    const gn = new GhostNet({ endpoint: 'wss://relay.example.com' });
    expect(gn).toBeInstanceOf(GhostNet);
  });
});

// ── Messaging (unit-level, no real relay) ──────────────────────────

describe('Messaging — not connected', () => {
  it('throws ConnectionError when sending without connection', async () => {
    const gn = new GhostNet();
    gn.createIdentity();
    // Not connected, so send should fail
    await expect(gn.send('0x' + 'ab'.repeat(32), 'hello')).rejects.toThrow(ConnectionError);
  });
});

// ── Event System ───────────────────────────────────────────────────

describe('Event system', () => {
  it('supports on/off for all event types', () => {
    const gn = new GhostNet();
    const handlers = {
      message: vi.fn(),
      error: vi.fn(),
      connect: vi.fn(),
      disconnect: vi.fn(),
    };

    // Register
    gn.on('message', handlers.message);
    gn.on('error', handlers.error);
    gn.on('connect', handlers.connect);
    gn.on('disconnect', handlers.disconnect);

    // Unregister (should not throw)
    gn.off('message', handlers.message);
    gn.off('error', handlers.error);
    gn.off('connect', handlers.connect);
    gn.off('disconnect', handlers.disconnect);
  });
});

// ── Error Hierarchy ────────────────────────────────────────────────

describe('Error types', () => {
  it('GhostNetError is the base class', () => {
    const err = new GhostNetError('test', 'TEST');
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe('TEST');
  });

  it('ConnectionError has correct code', () => {
    const err = new ConnectionError('fail');
    expect(err).toBeInstanceOf(GhostNetError);
    expect(err.code).toBe('ERR_CONNECTION');
  });

  it('IdentityError has correct code', () => {
    const err = new IdentityError('fail');
    expect(err).toBeInstanceOf(GhostNetError);
    expect(err.code).toBe('ERR_IDENTITY');
  });

  it('EncryptionError has correct code', () => {
    const err = new EncryptionError('fail');
    expect(err).toBeInstanceOf(GhostNetError);
    expect(err.code).toBe('ERR_ENCRYPTION');
  });

  it('PeerNotFoundError includes peerId', () => {
    const err = new PeerNotFoundError('0xdead');
    expect(err).toBeInstanceOf(GhostNetError);
    expect(err.code).toBe('ERR_PEER_NOT_FOUND');
    expect(err.peerId).toBe('0xdead');
  });
});

// ── Encryption Edge Cases ──────────────────────────────────────────

describe('Encryption edge cases', () => {
  it('malformed ciphertext throws EncryptionError', async () => {
    // Import decrypt directly to test edge case
    const { decrypt, edPrivateToX25519 } = await import('../../src/crypto/encryption.js');
    const { createIdentity } = await import('../../src/crypto/identity.js');

    const id = createIdentity();
    const x25519Priv = edPrivateToX25519(id.privateKeyBytes);

    // Malformed payload (too short)
    const malformed = new Uint8Array([1, 2, 3]);
    expect(() => decrypt(malformed, x25519Priv)).toThrow(EncryptionError);
  });

  it('encrypt/decrypt roundtrip works', async () => {
    const { encrypt, decrypt, edPrivateToX25519, edPublicToX25519 } =
      await import('../../src/crypto/encryption.js');
    const { createIdentity } = await import('../../src/crypto/identity.js');

    const recipient = createIdentity();
    const recipientX25519Pub = edPublicToX25519(recipient.publicKeyBytes);
    const recipientX25519Priv = edPrivateToX25519(recipient.privateKeyBytes);

    const plaintext = 'hello ghostnet';
    const packet = encrypt(plaintext, recipientX25519Pub);
    const decrypted = decrypt(packet, recipientX25519Priv);

    expect(decrypted).toBe(plaintext);
  });
});

// ── Live Relay Tests (skipped unless GHOSTNET_RELAY_URL is set) ────

const RELAY_URL = process.env['GHOSTNET_RELAY_URL'];
const describeRelay = RELAY_URL ? describe : describe.skip;

describeRelay('Live relay integration', () => {
  let gn1: GhostNet;
  let gn2: GhostNet;

  beforeEach(() => {
    gn1 = new GhostNet({ endpoint: RELAY_URL!, debug: false });
    gn2 = new GhostNet({ endpoint: RELAY_URL!, debug: false });
  });

  afterEach(() => {
    gn1.disconnect();
    gn2.disconnect();
  });

  it('connect fires connect event', async () => {
    gn1.createIdentity();
    const connected = new Promise<void>((resolve) => {
      gn1.on('connect', () => resolve());
    });
    await gn1.connect();
    await connected;
  });

  it('disconnect fires disconnect event', async () => {
    gn1.createIdentity();
    const disconnected = new Promise<string>((resolve) => {
      gn1.on('disconnect', (reason) => resolve(reason));
    });
    await gn1.connect();
    gn1.disconnect();
    const reason = await disconnected;
    expect(reason).toBeDefined();
  });

  it('send message between two peers', async () => {
    const id1 = gn1.createIdentity();
    const id2 = gn2.createIdentity();

    const received = new Promise<{ from: string; data: string }>((resolve) => {
      gn2.on('message', (msg) => resolve(msg));
    });

    await Promise.all([gn1.connect(), gn2.connect()]);

    // Wait for peer announcements to propagate
    await new Promise((r) => setTimeout(r, 1000));

    await gn1.send(id2.nodeId, 'hello from peer 1');
    const msg = await received;

    expect(msg.from).toBe(id1.nodeId);
    expect(msg.data).toBe('hello from peer 1');
  });
});
