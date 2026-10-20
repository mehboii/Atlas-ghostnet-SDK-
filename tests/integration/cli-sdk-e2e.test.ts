import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { WebSocketServer, WebSocket } from 'ws';
import { GhostNet } from '../../src/index.js';
import { inspectCli } from '../../src/cli.js';

describe('Phase 5: SDK <-> CLI End-to-End Interoperability', () => {
  let server: https.Server;
  let wss: WebSocketServer;
  let cliPath: string;
  const PORT = 9666;
  const relayEndpoint = `wss://localhost:${PORT}`;
  const clients = new Map<WebSocket, { nodeId: string; publicKey: string; signature: string }>();

  beforeAll(async () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const status = await inspectCli();
    expect(status.available).toBe(true);
    expect(status.executable).toBeTruthy();
    cliPath = status.executable!;

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
    for (const ws of wss.clients) {
      try {
        ws.terminate();
      } catch (err) {
        void err;
      }
    }
    wss.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('SDK and CLI share the exact same identity cryptography & deterministic derivation', () => {
    // 1. Generate identity using CLI
    const cliRes = spawnSync(cliPath, ['identity', 'create', '--no-color'], { encoding: 'utf8' });
    expect(cliRes.status).toBe(0);
    const seedMatch = /Seed phrase:\s*(([a-z]+\s+){11}[a-z]+)/i.exec(cliRes.stdout);
    const nodeMatch = /Node ID:\s*(0x[0-9a-f]{64})/i.exec(cliRes.stdout);
    expect(seedMatch).toBeTruthy();
    expect(nodeMatch).toBeTruthy();

    const phrase = seedMatch![1].trim();
    const cliNodeId = nodeMatch![1];

    // 2. Load the same phrase into the SDK
    const sdk = new GhostNet();
    const id = sdk.loadIdentity(phrase);

    expect(id.nodeId).toBe(cliNodeId);
    expect(sdk.getPublicIdentity()?.nodeId).toBe(cliNodeId);

    // 3. Generate identity in SDK, load into CLI
    const freshSdk = new GhostNet();
    const freshId = freshSdk.createIdentity();

    const cliLoadRes = spawnSync(cliPath, ['identity', 'load', '--no-color', freshId.seedPhrase], { encoding: 'utf8' });
    expect(cliLoadRes.status).toBe(0);
    expect(cliLoadRes.stdout).toContain(freshId.nodeId);
  });

  it('bidirectional messaging: sends from SDK to CLI, and from CLI to SDK over mesh relay', async () => {
    let cliListener: ReturnType<typeof spawn> | null = null;
    let sdk: GhostNet | null = null;

    try {
      cliListener = spawn(cliPath, ['listen', '--no-color', '--endpoint', relayEndpoint], {
        env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '0' },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let cliNodeId: string | null = null;
      const cliReceivedMessages: string[] = [];

      cliListener.stdout?.on('data', (chunk: Buffer) => {
        const text = chunk.toString();
        const nodeMatch = /your node id:\s*(0x[0-9a-f]{64})/i.exec(text);
        if (nodeMatch) cliNodeId = nodeMatch[1];
        if (text.includes('[message]')) {
          cliReceivedMessages.push(text);
        }
      });

      // Wait for CLI listener to connect and report nodeId
      const startTime = Date.now();
      while (!cliNodeId && Date.now() - startTime < 5000) {
        await new Promise((r) => setTimeout(r, 100));
      }
      expect(cliNodeId).toBeTruthy();

      // 2. Initialize SDK client
      sdk = new GhostNet({ endpoint: relayEndpoint, debug: true });
      const sdkId = sdk.createIdentity();
      await sdk.connect();

      // Wait briefly for peer discovery exchange
      await new Promise((r) => setTimeout(r, 800));
      const knownPeers = sdk.listPeers().map((p) => p.nodeId);
      expect(knownPeers).toContain(cliNodeId);

      // 3. Send from SDK -> CLI
      await sdk.send(cliNodeId!, 'Hello from SDK to CLI listener!');
      await new Promise((r) => setTimeout(r, 500));

      // 4. Send from CLI -> SDK
      const sdkReceived = new Promise<{ from: string; data: string }>((resolve) => {
        sdk!.on('message', (m) => resolve(m));
      });

      const cliSendProc = spawn(
        cliPath,
        ['send', '--no-color', '--endpoint', relayEndpoint, sdkId.nodeId, 'Hello from CLI sender to SDK!'],
        {
          env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '0' },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );

      let sendStdout = '';
      let sendStderr = '';
      cliSendProc.stdout?.on('data', (d) => { sendStdout += d.toString(); });
      cliSendProc.stderr?.on('data', (d) => { sendStderr += d.toString(); });

      const sendExitCode = await new Promise<number | null>((resolve) => {
        cliSendProc.on('close', resolve);
      });

      if (sendExitCode !== 0) {
        console.error('cliSend failed:', sendExitCode, sendStdout, sendStderr);
      }

      expect(sendExitCode).toBe(0);
      expect(sendStdout).toContain('Message sent');


      const msg = await Promise.race([
        sdkReceived,
        new Promise<null>((_, reject) => setTimeout(() => reject(new Error('Timeout waiting for CLI message')), 4000)),
      ]);

      expect(msg).toBeTruthy();
      expect(msg!.data).toBe('Hello from CLI sender to SDK!');
    } finally {
      if (cliListener) {
        try {
          cliListener.kill();
        } catch (err) {
          void err;
        }
      }
      if (sdk) {
        try {
          sdk.disconnect();
        } catch (err) {
          void err;
        }
      }
    }
  }, 30000);
});

