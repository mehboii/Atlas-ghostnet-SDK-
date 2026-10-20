/**
 * GhostNet crypto stack — end-to-end test harness.
 *
 * Runs the REAL exported crypto helpers from src/crypto/* against fixed,
 * published test vectors (no mocks, no re-implementation). Prints ✓/✗ per
 * check and exits non-zero if anything fails.
 *
 *   Run:  npx tsx scripts/crypto-harness.ts
 *   (from the `ghostnet sdk` directory)
 *
 * ─────────────────────────────────────────────────────────────────────────
 * ⚠️  SPEC vs LIVE STACK MISMATCH (flagged, not silently adapted)
 *
 * The requested spec named primitives that DO NOT EXIST in this codebase. The
 * live SDK crypto (src/crypto/*.ts, deps in package.json) actually uses:
 *
 *   Requested            Live reality (what this harness tests)
 *   ───────────────────  ────────────────────────────────────────────────
 *   1 secp256k1 identity  Ed25519 identity (@noble/curves/ed25519), key =
 *                          first 32B of BIP-39 seed (bip39). No SLIP-0010,
 *                          no secp256k1 anywhere.
 *   2 keccak256           BLAKE3 (@noble/hashes/blake3) for the node ID.
 *                          There is NO keccak256 in the stack. This harness
 *                          tests BLAKE3 and proves it differs from both
 *                          keccak256 and SHA3-256.
 *   3 PBKDF2 (PIN+salt)   HKDF-SHA256 (@noble/hashes/hkdf) over an X25519
 *                          ECDH shared secret. No PBKDF2, no PIN derivation.
 *                          (GhostFAQ.ts *claims* Argon2id PIN hashing — that
 *                          is stale marketing text with no implementation.)
 *   4 AES-256-GCM         AES-256-GCM (@noble/ciphers/aes) — present, but as
 *                          the symmetric leg of hybrid X25519+HKDF encryption,
 *                          keyed per-message. "wrong key" => wrong recipient.
 *   5 Ed25519 signing     Ed25519 sign/verify (@noble/curves/ed25519). Match.
 * ─────────────────────────────────────────────────────────────────────────
 */

import { createIdentity, loadIdentity } from '../src/crypto/identity.ts';
import { sign, verify } from '../src/crypto/signing.ts';
import {
  encrypt,
  decrypt,
  edPrivateToX25519,
  edPublicToX25519,
} from '../src/crypto/encryption.ts';
import { blake3 } from '@noble/hashes/blake3';
import { keccak_256, sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

// ── Tiny assertion framework ────────────────────────────────────────────
let passed = 0;
let failed = 0;

function fmt(v: unknown): string {
  if (v instanceof Uint8Array) return bytesToHex(v);
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}

function pass(name: string): void {
  passed++;
  console.log(`  ✓ ${name}`);
}

function fail(name: string, expected: unknown, actual: unknown): void {
  failed++;
  console.log(`  ✗ ${name}`);
  console.log(`      expected: ${fmt(expected)}`);
  console.log(`      actual:   ${fmt(actual)}`);
}

function assertEq(name: string, actual: unknown, expected: unknown): void {
  if (fmt(actual) === fmt(expected)) pass(name);
  else fail(name, expected, actual);
}

function assertTrue(name: string, actual: boolean): void {
  if (actual === true) pass(name);
  else fail(name, true, actual);
}

function assertFalse(name: string, actual: boolean): void {
  if (actual === false) pass(name);
  else fail(name, false, actual);
}

/** Passes only if `fn` throws. */
function assertThrows(name: string, fn: () => unknown): void {
  try {
    fn();
    fail(name, 'an exception', 'no exception thrown');
  } catch {
    pass(name);
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
}

// ── Fixed test vectors (published / cross-run stable) ───────────────────

// Canonical BIP-39 12-word mnemonic (all-zero entropy, valid checksum).
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Ed25519 identity derived from TEST_MNEMONIC by the LIVE code (captured from
// src/crypto/identity.ts — deterministic across runs and SDK versions).
const EXPECTED_PUBKEY =
  'c5785e1865b708938aff8161d573006496663b1aa10834e396dc566869a2c66a';
const EXPECTED_NODEID =
  '0x54b0936b31a9244bf94b3e255b4903f5df530329f7371015bfcbcfca9f6187cc';

// Published hash vectors.
const BLAKE3_EMPTY =
  'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262';
const BLAKE3_ABC =
  '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85';
const KECCAK256_EMPTY =
  'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
const SHA3_256_EMPTY =
  'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a';

// ── 1. Identity (LIVE: Ed25519 from BIP-39, NOT secp256k1) ──────────────
function testIdentity(): void {
  section('1. Identity  [LIVE: Ed25519 + BIP-39 — spec said secp256k1: MISMATCH]');

  const id1 = loadIdentity(TEST_MNEMONIC);
  const id2 = loadIdentity(TEST_MNEMONIC);

  // Deterministic: same seed phrase -> same pubkey/nodeId, across calls.
  assertEq('same seed -> same pubkey (deterministic)', id1.publicKey, id2.publicKey);
  assertEq('same seed -> same nodeId (deterministic)', id1.nodeId, id2.nodeId);

  // Stable against a captured cross-run vector.
  assertEq('pubkey matches fixed vector', id1.publicKey, EXPECTED_PUBKEY);
  assertEq('nodeId matches fixed vector', id1.nodeId, EXPECTED_NODEID);

  // Sign with the identity key, verify, then a tampered message must FAIL.
  const msg = utf8ToBytes('ghostnet identity message');
  const sig = sign(msg, id1.privateKeyBytes);
  assertTrue('sign + verify (identity key)', verify(sig, msg, id1.publicKeyBytes));

  const tampered = utf8ToBytes('ghostnet identity messagE');
  assertFalse('tampered message FAILS verification', verify(sig, tampered, id1.publicKeyBytes));

  id1.dispose();
  id2.dispose();
}

// ── 2. Hash (LIVE: BLAKE3, NOT keccak256) ───────────────────────────────
function testHash(): void {
  section('2. Hash  [LIVE: BLAKE3 nodeId — spec said keccak256: MISMATCH]');

  // The live node ID hash is BLAKE3 — assert against published vectors.
  assertEq('BLAKE3("") matches vector', bytesToHex(blake3(new Uint8Array())), BLAKE3_EMPTY);
  assertEq('BLAKE3("abc") matches vector', bytesToHex(blake3(utf8ToBytes('abc'))), BLAKE3_ABC);

  // Prove the live nodeId is BLAKE3(pubkey), not keccak/sha3.
  const id = loadIdentity(TEST_MNEMONIC);
  const recomputed = '0x' + bytesToHex(blake3(id.publicKeyBytes));
  assertEq('nodeId == 0x+BLAKE3(pubkey)', id.nodeId, recomputed);
  id.dispose();

  // Confirm keccak256 !== SHA3-256 !== BLAKE3 (different algorithms).
  const empty = new Uint8Array();
  const k = bytesToHex(keccak_256(empty));
  const s = bytesToHex(sha3_256(empty));
  const b = bytesToHex(blake3(empty));
  assertEq('keccak256("") matches vector', k, KECCAK256_EMPTY);
  assertEq('sha3-256("") matches vector', s, SHA3_256_EMPTY);
  assertTrue('keccak256 != sha3-256 (distinct algos)', k !== s);
  assertTrue('BLAKE3 != keccak256 and != sha3-256', b !== k && b !== s);
  if (k === s) console.log(`      keccak=${k}\n      sha3  =${s}`);
}

// ── 3. Key derivation (LIVE: HKDF-SHA256 over ECDH, NOT PBKDF2) ──────────
function testKeyDerivation(): void {
  section('3. Key derivation  [LIVE: HKDF-SHA256 over X25519 ECDH — spec said PBKDF2/PIN: MISMATCH]');

  // The KDF (deriveAesKey) is internal; exercise it through the real exported
  // encrypt/decrypt helpers. A successful decrypt proves the recipient
  // re-derived the identical AES key from the ECDH shared secret => the KDF
  // is deterministic. (Spec's "wrong PIN -> different key" maps to "wrong
  // recipient key -> different derived key -> decryption fails".)
  const recipient = createIdentity();
  const rPub = edPublicToX25519(recipient.publicKeyBytes);
  const rPriv = edPrivateToX25519(recipient.privateKeyBytes);

  const plaintext = 'derive-me';
  const packetA = encrypt(plaintext, rPub);
  const packetB = encrypt(plaintext, rPub);

  // Deterministic recipient-side derivation across two independent exchanges.
  assertEq('HKDF reproduces key (decrypt #1)', decrypt(packetA, rPriv), plaintext);
  assertEq('HKDF reproduces key (decrypt #2)', decrypt(packetB, rPriv), plaintext);

  // Wrong "key" (different recipient) derives a different AES key -> fails.
  const wrong = createIdentity();
  const wrongPriv = edPrivateToX25519(wrong.privateKeyBytes);
  assertThrows('wrong key -> different derived key -> FAILS', () => decrypt(packetA, wrongPriv));

  recipient.dispose();
  wrong.dispose();
}

// ── 4. AES-256-GCM (LIVE: inside hybrid encrypt/decrypt) ────────────────
function testAesGcm(): void {
  section('4. AES-256-GCM  [LIVE: hybrid X25519+HKDF+AES-GCM]');

  const recipient = createIdentity();
  const rPub = edPublicToX25519(recipient.publicKeyBytes);
  const rPriv = edPrivateToX25519(recipient.privateKeyBytes);

  const plaintext = 'vault payload \u{1F510} unicode ok';
  const packet = encrypt(plaintext, rPub);

  // Round-trip equality.
  assertEq('encrypt -> decrypt round-trip', decrypt(packet, rPriv), plaintext);

  // Bit-flip in the GCM ciphertext/tag must fail authentication.
  const flipped = packet.slice();
  flipped[flipped.length - 1] ^= 0x01;
  assertThrows('bit-flipped ciphertext FAILS (auth tag)', () => decrypt(flipped, rPriv));

  // Wrong key must fail.
  const wrong = createIdentity();
  const wrongPriv = edPrivateToX25519(wrong.privateKeyBytes);
  assertThrows('wrong key FAILS decryption', () => decrypt(packet, wrongPriv));

  // Fresh random nonce per encryption (packet layout: [pub 32][nonce 12][ct]).
  const N = 8;
  const nonces = new Set<string>();
  for (let i = 0; i < N; i++) {
    const p = encrypt(plaintext, rPub);
    nonces.add(bytesToHex(p.slice(32, 44)));
  }
  assertEq(`unique nonce per encrypt (${N} runs)`, nonces.size, N);

  recipient.dispose();
  wrong.dispose();
}

// ── 5. Ed25519 NAT signing (LIVE: matches spec) ─────────────────────────
function testEd25519Signing(): void {
  section('5. Ed25519 signing  [LIVE: matches spec]');

  const id = createIdentity();
  const payload = utf8ToBytes('NAT-traversal announce packet');
  const sig = sign(payload, id.privateKeyBytes);

  assertEq('signature is 64 bytes', sig.length, 64);
  assertTrue('generate + sign + verify', verify(sig, payload, id.publicKeyBytes));

  const tampered = utf8ToBytes('NAT-traversal announce packeX');
  assertFalse('tampered payload FAILS verification', verify(sig, tampered, id.publicKeyBytes));

  id.dispose();
}

// ── Runner ──────────────────────────────────────────────────────────────
function main(): void {
  console.log('GhostNet crypto stack — live end-to-end harness');
  console.log('================================================');

  const suites: Array<[string, () => void]> = [
    ['identity', testIdentity],
    ['hash', testHash],
    ['kdf', testKeyDerivation],
    ['aes-gcm', testAesGcm],
    ['ed25519', testEd25519Signing],
  ];

  for (const [name, fn] of suites) {
    try {
      fn();
    } catch (err) {
      failed++;
      console.log(`  ✗ ${name} suite crashed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const total = passed + failed;
  console.log('\n================================================');
  console.log(`Summary: ${passed}/${total} passed`);
  if (failed > 0) {
    console.log(`✗ ${failed} check(s) FAILED`);
    process.exit(1);
  }
  console.log('✓ all checks passed');
  process.exit(0);
}

main();
