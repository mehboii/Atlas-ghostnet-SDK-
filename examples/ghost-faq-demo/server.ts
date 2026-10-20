/**
 * ghost-faq-demo/server — Local web server for GhostSupportBot.
 *
 * Usage:
 *   npx tsx examples/ghost-faq-demo/server.ts
 *   Then open http://localhost:3777
 */
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GhostSupportBot } from '../../src/index.js';

const bot = new GhostSupportBot();
const PORT = 3777;
export const MAX_REQUEST_BODY_BYTES = 16 * 1024;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createGhostFaqServer(): http.Server {
  return http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    const htmlPath = path.join(__dirname, 'index.html');
    const html = fs.readFileSync(htmlPath, 'utf-8');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
    return;
  }

  if (req.method === 'GET' && req.url === '/logo.png') {
    const logoPath = path.join(__dirname, 'logo.png');
    const logo = fs.readFileSync(logoPath);
    res.writeHead(200, { 'Content-Type': 'image/png' });
    res.end(logo);
    return;
  }

  if (req.method === 'POST' && req.url === '/ask') {
    const declaredLength = Number(req.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Request body too large' }));
      return;
    }

    let body = '';
    let bodyBytes = 0;
    let rejected = false;
    req.on('data', (chunk: Buffer) => {
      if (rejected) return;
      bodyBytes += chunk.byteLength;
      if (bodyBytes > MAX_REQUEST_BODY_BYTES) {
        rejected = true;
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Request body too large' }));
        return;
      }
      body += chunk.toString();
    });
    req.on('end', () => {
      if (rejected) return;
      try {
        const { message } = JSON.parse(body);
        const reply = bot.ask(message ?? '');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ reply }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request body' }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  createGhostFaqServer().listen(PORT, '127.0.0.1', () => {
    console.log(`GhostNet Support Terminal running at http://localhost:${PORT}`);
  });
}
