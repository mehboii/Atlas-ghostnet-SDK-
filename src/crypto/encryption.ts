import { x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';
import { EncryptionError } from '../errors.js';

const HKDF_INFO = new TextEncoder().encode('ghostnet-packet-encryption');
const NONCE_LENGTH = 12;
const KEY_LENGTH = 32;
const EPHEMERAL_PUB_LENGTH = 32;

/**
 * Derive a 256-bit AES key from an X25519 shared secret via HKDF-SHA256.
 *
 * Uses the same `info` parameter as the main GhostNet app for compatibility.
 */
function deriveAesKey(sharedSecret: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, undefined, HKDF_INFO, KEY_LENGTH);
}

/**
 * Encrypt a message for a recipient using hybrid encryption.
 *
 * Scheme (matches GhostNet main app):
 *   1. Generate ephemeral X25519 keypair
 *   2. ECDH with recipient's X25519 public key → shared secret
 *   3. HKDF-SHA256(shared secret, info="ghostnet-packet-encryption") → AES key
 *   4. AES-256-GCM encrypt the plaintext
 *   5. Output: [ephemeral pubkey 32B] + [nonce 12B] + [ciphertext+tag]
 *
 * @param plaintext  - UTF-8 message to encrypt.
 * @param recipientX25519Pub - Recipient's 32-byte X25519 public key.
 * @returns Encrypted packet as Uint8Array.
 *
 * @example
 * ```ts
 * const packet = encrypt('hello', recipientPubBytes);
 * ```
 */
export function encrypt(
  plaintext: string,
  recipientX25519Pub: Uint8Array,
): Uint8Array {
  let ephemeralPriv: Uint8Array | null = null;
  let shared: Uint8Array | null = null;
  let aesKey: Uint8Array | null = null;
  try {
    ephemeralPriv = x25519.utils.randomPrivateKey();
    const ephemeralPub = x25519.getPublicKey(ephemeralPriv);
    shared = x25519.getSharedSecret(ephemeralPriv, recipientX25519Pub);

    aesKey = deriveAesKey(shared);
    const nonce = randomBytes(NONCE_LENGTH);

    const plaintextBytes = new TextEncoder().encode(plaintext);
    const cipher = gcm(aesKey, nonce);
    const ciphertext = cipher.encrypt(plaintextBytes);

    // Pack: [ephemeral pub 32] [nonce 12] [ciphertext+tag]
    const packet = new Uint8Array(
      EPHEMERAL_PUB_LENGTH + NONCE_LENGTH + ciphertext.byteLength,
    );
    packet.set(ephemeralPub, 0);
    packet.set(nonce, EPHEMERAL_PUB_LENGTH);
    packet.set(ciphertext, EPHEMERAL_PUB_LENGTH + NONCE_LENGTH);
    return packet;
  } catch (err) {
    if (err instanceof EncryptionError) throw err;
    throw new EncryptionError(
      `Encryption failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    if (ephemeralPriv) ephemeralPriv.fill(0);
    if (shared) shared.fill(0);
    if (aesKey) aesKey.fill(0);
  }
}

/**
 * Decrypt an incoming packet using the recipient's X25519 private key.
 *
 * Reverses the hybrid encryption scheme used by {@link encrypt}.
 *
 * @param packet  - The raw encrypted packet (ephemeral pub + nonce + ciphertext).
 * @param recipientX25519Priv - Recipient's 32-byte X25519 private key.
 * @returns Decrypted UTF-8 string.
 *
 * @example
 * ```ts
 * const message = decrypt(packet, myPrivKeyBytes);
 * ```
 */
export function decrypt(
  packet: Uint8Array,
  recipientX25519Priv: Uint8Array,
): string {
  let shared: Uint8Array | null = null;
  let aesKey: Uint8Array | null = null;
  try {
    if (packet.length < EPHEMERAL_PUB_LENGTH + NONCE_LENGTH + 16) {
      throw new Error('Packet too short');
    }

    const ephemeralPub = packet.slice(0, EPHEMERAL_PUB_LENGTH);
    const nonce = packet.slice(
      EPHEMERAL_PUB_LENGTH,
      EPHEMERAL_PUB_LENGTH + NONCE_LENGTH,
    );
    const ciphertext = packet.slice(EPHEMERAL_PUB_LENGTH + NONCE_LENGTH);

    shared = x25519.getSharedSecret(recipientX25519Priv, ephemeralPub);
    aesKey = deriveAesKey(shared);
    const cipher = gcm(aesKey, nonce);
    const plaintextBytes = cipher.decrypt(ciphertext);

    return new TextDecoder().decode(plaintextBytes);
  } catch (err) {
    if (err instanceof EncryptionError) throw err;
    throw new EncryptionError(
      `Decryption failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    if (shared) shared.fill(0);
    if (aesKey) aesKey.fill(0);
  }
}

/**
 * @internal
 * Convert an Ed25519 private key seed (first 32 bytes) to an X25519 private key.
 *
 * Ed25519 and X25519 share the same underlying curve (Curve25519).
 * The conversion hashes the seed with SHA-512 and clamps the result,
 * but @noble/curves handles this internally — we just need the raw
 * 32-byte seed as the X25519 private scalar.
 *
 * @param ed25519Seed - The 32-byte Ed25519 private key seed.
 * @returns 32-byte X25519 private key.
 *
 * @example
 * ```ts
 * const x25519Priv = edPrivateToX25519(seed);
 * ```
 */
export function edPrivateToX25519(ed25519Seed: Uint8Array): Uint8Array {
  return edwardsToMontgomeryPriv(ed25519Seed);
}

/**
 * @internal
 * Convert an Ed25519 public key to an X25519 public key.
 *
 * Uses the birational map from the Ed25519 (twisted Edwards) point
 * to the corresponding Montgomery (X25519) u-coordinate.
 *
 * @param ed25519Pub - 32-byte Ed25519 public key.
 * @returns 32-byte X25519 public key.
 *
 * @example
 * ```ts
 * const x25519Pub = edPublicToX25519(identity.publicKey);
 * ```
 */
export function edPublicToX25519(ed25519Pub: Uint8Array): Uint8Array {
  return edwardsToMontgomeryPub(ed25519Pub);
}
