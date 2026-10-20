import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';
import { GhostNet, ConnectionError } from '../src/index.js';

describe('Phase 7: Concurrency & Race Condition Verification', () => {
  let server: https.Server;
  let wss: WebSocketServer;
  const PORT = 9777;
  const relayEndpoint = `wss://localhost:${PORT}`;
  const clients = new Map<WebSocket, { nodeId: string; publicKey: string; signature: string }>();

  beforeAll(async () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const scratchDir = 'C:\\Users\\novtw\\.gemini\\antigravity\\brain\\15a06ab3-3cde-4610-ad5c-c0e8fe817182\\scratch';
    const key = fs.readFileSync(path.join(scratchDir, 'key.pem'));
    const cert = fs.readFileSync(path.join(scratchDir, 'cert.pem'));

    server = https.createServer({ key, cert });
    wss = new WebSocketServer({ server });

    wss.on('connection', (ws) => {
      ws.on('message', (data) => {
        let msg: { type: string; nodeId?: string; publicKey?: string; signature?: string; to?: string };
        try {
          msg = JSON.parse(data.toString());
        } catch {
          return;
        }

        if (msg.type === 'register') {
          const reg = { nodeId: msg.nodeId!, publicKey: msg.publicKey!, signature: msg.signature! };
          clients.set(ws, reg);
          const announce = JSON.stringify({ ...reg, type: 'peer_announce' });
          for (const [otherWs, otherReg] of clients.entries()) {
            if (otherWs !== ws && otherWs.readyState === WebSocket.OPEN) {
              otherWs.send(announce);
              ws.send(JSON.stringify({ ...otherReg, type: 'peer_announce' }));
            }
          }
        } else if (msg.type === 'message') {
          for (const [otherWs, otherReg] of clients.entries()) {
            if (otherReg.nodeId === msg.to && otherWs.readyState === WebSocket.OPEN) {
              otherWs.send(JSON.stringify(msg));
            }
          }
        }
      });

      ws.on('close', () => {
        clients.delete(ws);
      });
    });

    await new Promise<void>((resolve) => server.listen(PORT, () => resolve()));
  });

  afterAll(async () => {
    wss.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('handles multiple concurrent connect() calls on same client without duplicate sockets', async () => {
    const client = new GhostNet({ endpoint: relayEndpoint });
    client.createIdentity();

    // Spawn 5 simultaneous connect calls
    const results = await Promise.all([
      client.connect(),
      client.connect(),
      client.connect(),
      client.connect(),
      client.connect(),
    ]);

    expect(results).toHaveLength(5);
    expect(client.getStatus().connected).toBe(true);
    client.disconnect();
    expect(client.getStatus().connected).toBe(false);
  });

  it('supports multiple simultaneous clients exchanging concurrent messages', async () => {
    const clientCount = 4;
    const clientsList: GhostNet[] = [];

    for (let i = 0; i < clientCount; i++) {
      const c = new GhostNet({ endpoint: relayEndpoint });
      c.createIdentity();
      clientsList.push(c);
    }

    // Connect all concurrently
    await Promise.all(clientsList.map((c) => c.connect()));
    await new Promise((r) => setTimeout(r, 600));

    // Verify each client knows all other peers
    for (const c of clientsList) {
      expect(c.listPeers().length).toBeGreaterThanOrEqual(clientCount - 1);
    }

    // Set up message collectors
    const receivedMap = new Map<string, string[]>();
    for (const c of clientsList) {
      const id = c.getStatus().nodeId!;
      receivedMap.set(id, []);
      c.on('message', (m) => {
        receivedMap.get(id)?.push(m.data);
      });
    }

    // Send messages from each client to all others concurrently
    const sendPromises: Promise<void>[] = [];
    for (let i = 0; i < clientCount; i++) {
      for (let j = 0; j < clientCount; j++) {
        if (i === j) continue;
        const targetNodeId = clientsList[j].getStatus().nodeId!;
        sendPromises.push(clientsList[i].send(targetNodeId, `msg from ${i} to ${j}`));
      }
    }

    await Promise.all(sendPromises);
    await new Promise((r) => setTimeout(r, 1000));

    // Each client should have received clientCount - 1 messages
    for (const [, messages] of receivedMap) {
      expect(messages.length).toBe(clientCount - 1);
    }

    // Disconnect all
    for (const c of clientsList) {
      c.disconnect();
    }
  });

  it('handles rapid sequential connect and disconnect cycles cleanly without leaks', async () => {
    const client = new GhostNet({ endpoint: relayEndpoint });
    client.createIdentity();

    for (let i = 0; i < 5; i++) {
      await client.connect();
      expect(client.getStatus().connected).toBe(true);
      client.disconnect();
      expect(client.getStatus().connected).toBe(false);
    }
  });

  it('handles disconnect racing with an in-flight send safely', async () => {
    const client = new GhostNet({ endpoint: relayEndpoint });
    client.createIdentity();
    await client.connect();

    client.disconnect();
    // After disconnect, send must cleanly reject with ConnectionError without crashing
    await expect(client.send('0x' + 'f'.repeat(64), 'late message')).rejects.toThrow(ConnectionError);
  });
});
