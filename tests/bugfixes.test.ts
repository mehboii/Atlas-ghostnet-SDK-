/**
 * Regression tests for bugs found during the full-codebase audit.
 *
 * Bug A: transport referenced global `WebSocket.OPEN` (ReferenceError on Node < 22)
 * Bug B: nonce registry had no hard memory cap (unbounded growth under load)
 * Bug C: nonce was recorded before signature/freshness checks (registry pollution)
 * Bug D: disconnect() during the connecting phase leaked the socket
 */
import { describe, it, expect, vi } from 'vitest';
import { GhostNet } from '../src/client.js';
import { Transport } from '../src/transport.js';
import { Logger } from '../src/logger.js';
import { createIdentity } from '../src/crypto/identity.js';
import { sign } from '../src/crypto/signing.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import { blake3 } from '@noble/hashes/blake3';

const NONCE_REGISTRY_MAX = 10_000;

interface GhostNetInternals {
  handleIncoming: (raw: string) => Promise<void>;
  seenNonces: Map<string, number>;
  checkNonce: (nonce: string, timestamp: number) => boolean;
}
function internals(gn: GhostNet): GhostNetInternals {
  return gn as unknown as GhostNetInternals;
}

function makeSignedEnvelope(
  sender: ReturnType<typeof createIdentity>,
  to: string,
  payload: string,
  opts: { nonce?: string; timestamp?: number } = {},
) {
  const nonce = opts.nonce ?? bytesToHex(randomBytes(16));
  const timestamp = opts.timestamp ?? Date.now();
  const payloadHash = bytesToHex(blake3(new TextEncoder().encode(payload)));
  const canonical = new TextEncoder().encode(
    `ghostnet:msg:v1:${nonce}:${timestamp}:${sender.nodeId}:${to}:${payloadHash}`,
  );
  return {
    type: 'message' as const,
    from: sender.nodeId,
    to,
    payload,
    encrypted: false,
    nonce,
    timestamp,
    signature: bytesToHex(sign(canonical, sender.privateKeyBytes)),
    senderPublicKey: sender.publicKey,
  };
}

// ─────────────────────────────────────────────────────────────
// Bug B: nonce registry must respect a hard memory cap
// ─────────────────────────────────────────────────────────────
describe('Bug B: nonce registry is bounded under sustained load', () => {
  it('checkNonce keeps the registry at or below NONCE_REGISTRY_MAX', () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test' });
    gn.createIdentity();
    const seen = internals(gn).seenNonces;
    const checkNonce = internals(gn).checkNonce.bind(gn);

    // Flood with more than the cap of recent (non-expirable) nonces.
    const now = Date.now();
    for (let i = 0; i < NONCE_REGISTRY_MAX + 5_000; i++) {
      // Insert directly with recent timestamps so the time-based sweep
      // cannot free them, forcing the hard-cap path.
      if (seen.size >= NONCE_REGISTRY_MAX) {
        // exercise checkNonce so the hard cap eviction runs
        checkNonce(`live-${i}`, now);
      } else {
        seen.set(`pre-${i}`, now);
      }
    }

    expect(seen.size).toBeLessThanOrEqual(NONCE_REGISTRY_MAX);
  });
});

// ─────────────────────────────────────────────────────────────
// Bug C: a forged message must not "burn" a nonce a real sender will use
// ─────────────────────────────────────────────────────────────
describe('Bug C: nonce recorded only after signature + freshness pass', () => {
  it('forged-signature message does not consume the nonce', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    const me = gn.createIdentity();

    const messages: Array<{ from: string; data: string }> = [];
    gn.on('message', (m) => messages.push(m));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const handleIncoming = internals(gn).handleIncoming.bind(gn);
    const sender = createIdentity();
    const sharedNonce = 'contested-nonce';

    // 1. Attacker sends a message with the target nonce but a bad signature.
    await handleIncoming(
      JSON.stringify({
        type: 'message',
        from: sender.nodeId,
        to: me.nodeId,
        payload: 'forged',
        encrypted: false,
        nonce: sharedNonce,
        timestamp: Date.now(),
        signature: bytesToHex(randomBytes(64)),
        senderPublicKey: sender.publicKey,
      }),
    );
    expect(messages).toHaveLength(0);
    // The forged attempt must NOT have recorded the nonce.
    expect(internals(gn).seenNonces.has(sharedNonce)).toBe(false);

    // 2. The legitimate sender now uses that same nonce — must be delivered.
    await handleIncoming(
      JSON.stringify(makeSignedEnvelope(sender, me.nodeId, 'legit', { nonce: sharedNonce })),
    );
    expect(messages).toHaveLength(1);
    expect(messages[0].data).toBe('legit');
  });

  it('stale message does not consume the nonce', async () => {
    const gn = new GhostNet({ endpoint: 'wss://dummy.test', requireEncryption: false });
    gn.createIdentity();
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const handleIncoming = internals(gn).handleIncoming.bind(gn);
    const sender = createIdentity();
    const nonce = 'stale-then-fresh';

    // Stale message (older than the freshness window) with a valid signature.
    await handleIncoming(
      JSON.stringify(
        makeSignedEnvelope(sender, '', 'old', {
          nonce,
          timestamp: Date.now() - 10 * 60 * 1000,
        }),
      ),
    );
    expect(internals(gn).seenNonces.has(nonce)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────
// Bug D: disconnect() during connect must abort the socket
// ─────────────────────────────────────────────────────────────
describe('Bug D: disconnect() aborts a still-connecting socket', () => {
  it('closes the socket created during connect()', () => {
    class FakeWS {
      static OPEN = 1;
      readyState = 0; // CONNECTING
      binaryType = '';
      onopen: (() => void) | null = null;
      onclose: ((e: { code: number; reason: string }) => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage: ((e: unknown) => void) | null = null;
      closed = false;
      // Intentionally never auto-opens — simulates a slow handshake.
      close() {
        this.closed = true;
        this.readyState = 3;
        this.onclose?.({ code: 1000, reason: 'client disconnect' });
      }
      send() {}
    }

    const original = globalThis.WebSocket;
    // @ts-expect-error — swap in a fake WebSocket for the test
    globalThis.WebSocket = FakeWS;
    try {
      const transport = new Transport('wss://slow.test', new Logger(false));
      // Do not await — the handshake never completes. Swallow the expected
      // rejection that fires when we abort.
      transport.connect().catch(() => {});

      // The fix tracks this.ws from construction, so the transport holds the
      // mid-handshake socket and disconnect() can abort it.
      const ws = (transport as unknown as { ws: FakeWS | null }).ws;
      expect(ws).toBeDefined();
      expect(ws!.closed).toBe(false);

      transport.disconnect();

      expect(ws!.closed).toBe(true);
      expect(transport.connected).toBe(false);
    } finally {
      // @ts-expect-error — restore original
      globalThis.WebSocket = original;
    }
  });
});
