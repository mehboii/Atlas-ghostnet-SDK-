import { describe, expect, it, vi } from 'vitest';
import { GhostNet } from '../src/client.js';
import { Logger } from '../src/logger.js';
import { Transport } from '../src/transport.js';

describe('endpoint secrets stay out of diagnostics', () => {
  const token = 'audit-secret-token-123';

  it('does not repeat rejected endpoint input in an error', () => {
    expect(() => new GhostNet({ endpoint: `ws://relay.test/?token=${token}` }))
      .toThrowError(expect.objectContaining({ message: expect.not.stringContaining(token) }));
    expect(() => new GhostNet({ endpoint: `wss://%/?token=${token}` }))
      .toThrowError(expect.objectContaining({ message: expect.not.stringContaining(token) }));
  });

  it('does not expose URL path or query secrets through status and transport diagnostics', async () => {
    const endpoint = `wss://relay.test/private/${token}?token=${token}`;
    const client = new GhostNet({ endpoint });
    expect(JSON.stringify(client.getStatus())).not.toContain(token);

    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {});
    class FailingSocket {
      binaryType = '';
      onopen: (() => void) | null = null;
      onclose: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage: (() => void) | null = null;
      constructor() { queueMicrotask(() => this.onerror?.()); }
      close() {}
    }
    const original = globalThis.WebSocket;
    globalThis.WebSocket = FailingSocket as unknown as typeof WebSocket;
    const transport = new Transport(endpoint, new Logger(true));
    try {
      await expect(transport.connect()).rejects.toThrowError(expect.objectContaining({
        message: expect.not.stringContaining(token),
      }));
      expect(JSON.stringify(debug.mock.calls)).not.toContain(token);
    } finally {
      globalThis.WebSocket = original;
      debug.mockRestore();
      transport.disconnect();
    }
  });

  it('redacts endpoint details from socket construction errors', async () => {
    const endpoint = `wss://relay.test/private/${token}?token=${token}`;
    const original = globalThis.WebSocket;
    class ThrowingSocket {
      constructor(url: string) { throw new Error(`Invalid WebSocket URL ${url}`); }
    }
    globalThis.WebSocket = ThrowingSocket as unknown as typeof WebSocket;
    try {
      const transport = new Transport(endpoint, new Logger(false));
      await expect(transport.connect()).rejects.toThrowError(expect.objectContaining({
        message: expect.not.stringContaining(token),
      }));
    } finally {
      globalThis.WebSocket = original;
    }
  });
});
