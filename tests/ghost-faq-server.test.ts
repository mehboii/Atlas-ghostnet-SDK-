import { afterEach, describe, expect, it } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createGhostFaqServer, MAX_REQUEST_BODY_BYTES } from '../examples/ghost-faq-demo/server.js';

describe('Ghost FAQ demo request limits', () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server?.listening) {
      await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
    }
  });

  async function startServer(): Promise<string> {
    server = createGhostFaqServer();
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
    const address = server.address() as AddressInfo;
    return `http://127.0.0.1:${address.port}`;
  }

  it('returns 413 for a declared oversized request body', async () => {
    const origin = await startServer();
    const response = await fetch(`${origin}/ask`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'x'.repeat(MAX_REQUEST_BODY_BYTES) }),
    });

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toEqual({ error: 'Request body too large' });
  });

  it('returns 413 for an oversized chunked request body', async () => {
    const origin = await startServer();
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('x'.repeat(MAX_REQUEST_BODY_BYTES)));
        controller.enqueue(new TextEncoder().encode('overflow'));
        controller.close();
      },
    });
    const response = await fetch(`${origin}/ask`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      duplex: 'half',
    } as RequestInit & { duplex: 'half' });

    expect(response.status).toBe(413);
  });

  it('continues to serve ordinary requests', async () => {
    const origin = await startServer();
    const response = await fetch(`${origin}/ask`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'How does encryption work?' }),
    });

    expect(response.status).toBe(200);
    const payload = await response.json() as { reply?: string };
    expect(payload.reply).toBeTypeOf('string');
    expect(payload.reply!.length).toBeGreaterThan(0);
  });
});
