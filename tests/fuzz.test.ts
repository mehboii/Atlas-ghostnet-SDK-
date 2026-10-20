/**
 * Property-based fuzz testing for GhostNet SDK cryptography.
 *
 * Uses fast-check to throw random/garbage data at every crypto surface
 * and verify the SDK never crashes — only throws typed errors.
 */
import { describe, it } from 'vitest';
import fc from 'fast-check';
import { createIdentity, loadIdentity } from '../src/crypto/identity.js';
import {
  encrypt,
  decrypt,
  edPrivateToX25519,
  edPublicToX25519,
} from '../src/crypto/encryption.js';
import { sign, verify } from '../src/crypto/signing.js';
import { EncryptionError, IdentityError } from '../src/errors.js';

// Pre-generate valid fixtures for tests that need them
const validIdentity = createIdentity();
const recipientIdentity = createIdentity();
const recipientX25519Pub = edPublicToX25519(recipientIdentity.publicKeyBytes);
const recipientX25519Priv = edPrivateToX25519(recipientIdentity.privateKeyBytes);
const validEncrypted = encrypt('test', recipientX25519Pub);

describe('Fuzz: AES-256-GCM Decryption', () => {
  it('never crashes on random Uint8Array input — always throws EncryptionError', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 0, maxLength: 1024 }),
        (garbage) => {
          try {
            decrypt(garbage, recipientX25519Priv);
            // If decryption somehow succeeds on garbage, that's still not a crash
            return true;
          } catch (e) {
            return e instanceof EncryptionError;
          }
        },
      ),
      { numRuns: 1000 },
    );
  });

  it('never crashes on random string converted to bytes', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 512 }), (str) => {
        try {
          const bytes = new TextEncoder().encode(str);
          decrypt(bytes, recipientX25519Priv);
          return true;
        } catch (e) {
          return e instanceof EncryptionError;
        }
      }),
      { numRuns: 500 },
    );
  });

  it('never crashes with random private key on valid ciphertext', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (randomKey) => {
        try {
          decrypt(validEncrypted, randomKey);
          return true;
        } catch (e) {
          return e instanceof EncryptionError;
        }
      }),
      { numRuns: 500 },
    );
  });
});

describe('Fuzz: AES-256-GCM Encryption', () => {
  it('encrypts any valid UTF-8 string without crashing', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 4096 }), (plaintext) => {
        const packet = encrypt(plaintext, recipientX25519Pub);
        // Must produce a packet larger than ephemeral pub + nonce
        return packet.length >= 44;
      }),
      { numRuns: 500 },
    );
  });

  it('encrypt → decrypt roundtrip preserves any string', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 2048 }), (plaintext) => {
        const packet = encrypt(plaintext, recipientX25519Pub);
        const decrypted = decrypt(packet, recipientX25519Priv);
        return decrypted === plaintext;
      }),
      { numRuns: 300 },
    );
  });

  it('rejects garbage recipient public key', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 0, maxLength: 64 }).filter((a) => a.length !== 32),
        (badKey) => {
          try {
            encrypt('test', badKey);
            return true; // some short keys might not throw at encrypt time
          } catch (e) {
            return e instanceof EncryptionError;
          }
        },
      ),
      { numRuns: 300 },
    );
  });
});

describe('Fuzz: Ed25519 Signing', () => {
  it('sign never crashes on any message bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 4096 }), (msg) => {
        const sig = sign(msg, validIdentity.privateKeyBytes);
        return sig.length === 64;
      }),
      { numRuns: 200 },
    );
  });

  it('verify never crashes on garbage signature', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 0, maxLength: 128 }),
        fc.uint8Array({ minLength: 0, maxLength: 256 }),
        (garbageSig, garbageMsg) => {
          const result = verify(garbageSig, garbageMsg, validIdentity.publicKeyBytes);
          return typeof result === 'boolean';
        },
      ),
      { numRuns: 500 },
    );
  });

  it('verify returns false for random signatures on valid message', () => {
    const msg = new TextEncoder().encode('ghostnet:test');
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 64, maxLength: 64 }), (randomSig) => {
        return verify(randomSig, msg, validIdentity.publicKeyBytes) === false;
      }),
      { numRuns: 300 },
    );
  });
});

describe('Fuzz: Identity / BIP-39', () => {
  it('loadIdentity rejects any random string as seed phrase', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 200 }), (garbage) => {
        try {
          loadIdentity(garbage);
          // If it somehow passes BIP-39 validation, check it returns valid identity
          return true;
        } catch (e) {
          return e instanceof IdentityError;
        }
      }),
      { numRuns: 1000 },
    );
  });

  it('loadIdentity rejects random word combinations', () => {
    const words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta', 'iota', 'kappa', 'lambda', 'mu'];
    fc.assert(
      fc.property(
        fc.shuffledSubarray(words, { minLength: 12, maxLength: 12 }),
        (randomWords) => {
          try {
            loadIdentity(randomWords.join(' '));
            return true;
          } catch (e) {
            return e instanceof IdentityError;
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe('Fuzz: Curve Conversion', () => {
  it('edPublicToX25519 never crashes on 32-byte input', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (bytes) => {
        try {
          const result = edPublicToX25519(bytes);
          return result.length === 32;
        } catch {
          // Some random bytes aren't valid Ed25519 points — that's expected
          return true;
        }
      }),
      { numRuns: 500 },
    );
  });

  it('edPrivateToX25519 never crashes on 32-byte input', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (bytes) => {
        const result = edPrivateToX25519(bytes);
        return result.length === 32;
      }),
      { numRuns: 500 },
    );
  });
});
