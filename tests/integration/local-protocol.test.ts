import { afterEach, describe, expect, it } from 'vitest';
import { GhostNet, PayloadTooLargeError } from '../../src/index.js';

type Frame = { type: string; nodeId?: string; publicKey?: string; signature?: string; to?: string };
const clients = new Set<LocalSocket>();
const priorWebSocket = globalThis.WebSocket;

class LocalSocket {
  readyState = 0;
  binaryType = 'arraybuffer';
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: ((event: { code: number; reason: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  registration: Frame | null = null;

  constructor(_url: string) {
    clients.add(this);
    queueMicrotask(() => { this.readyState = 1; this.onopen?.(); });
  }

  send(raw: string): void {
    const frame = JSON.parse(raw) as Frame;
    if (frame.type === 'register') {
      this.registration = frame;
      for (const client of clients) {
        if (client === this || !client.registration || client.readyState !== 1) continue;
        client.onmessage?.({ data: JSON.stringify({ ...frame, type: 'peer_announce' }) });
        this.onmessage?.({ data: JSON.stringify({ ...client.registration, type: 'peer_announce' }) });
      }
    } else if (frame.type === 'message') {
      for (const client of clients) {
        if (client.registration?.nodeId === frame.to && client.readyState === 1) {
          client.onmessage?.({ data: raw });
        }
      }
    }
  }

  close(): void {
    this.readyState = 3;
    clients.delete(this);
    this.onclose?.({ code: 1000, reason: 'closed' });
  }
}

afterEach(() => {
  globalThis.WebSocket = priorWebSocket;
  clients.clear();
});

describe('controlled relay protocol', () => {
  it('shares verified peer announcements and sends encrypted signed messages', async () => {
    globalThis.WebSocket = LocalSocket as unknown as typeof WebSocket;
    const alice = new GhostNet();
    const bob = new GhostNet();
    const aliceId = alice.createIdentity();
    const bobId = bob.createIdentity();
    const received = new Promise<string>((resolve) => bob.on('message', (m) => resolve(m.data)));
    await Promise.all([alice.connect(), alice.connect()]);
    expect(clients.size).toBe(1);
    await bob.connect();
    expect(alice.listPeers().map((p) => p.nodeId)).toContain(bobId.nodeId);
    expect(bob.listPeers().map((p) => p.nodeId)).toContain(aliceId.nodeId);
    expect(alice.getStatus().connected).toBe(true);
    await alice.send(bobId.nodeId, 'encrypted hello');
    expect(await received).toBe('encrypted hello');
    expect(alice.getPublicIdentity()?.nodeId).toBe(aliceId.nodeId);
    await expect(alice.send(bobId.nodeId, 'x'.repeat(65_537))).rejects.toBeInstanceOf(PayloadTooLargeError);
    alice.disconnect();
    bob.disconnect();
    expect(alice.getStatus().connected).toBe(false);
  });
});
