/**
 * hello-ghostnet — minimal example of using @n11x/atlas.
 *
 * Creates an identity, connects to the GhostNet mesh, sends a message
 * to a peer, logs any reply, then disconnects.
 *
 * Usage:
 *   npx tsx examples/hello-ghostnet/index.ts
 */
import { GhostNet } from '../../src/index.js';

const PEER_ID = process.argv[2] ?? '0x<paste-peer-node-id-here>';

async function main() {
  const gn = new GhostNet({ debug: true });

  // 1. Create a fresh identity (or load one with gn.loadIdentity(seedPhrase))
  const identity = gn.createIdentity();
  console.log('Your node ID:', identity.nodeId);
  console.log('Seed phrase (back this up!):', identity.seedPhrase);

  // 2. Listen for incoming messages
  gn.on('message', (msg) => {
    console.log(`Message from ${msg.from}: ${msg.data}`);
  });

  gn.on('error', (err) => {
    console.error('Error:', err.message);
  });

  gn.on('connect', () => {
    console.log('Connected to GhostNet mesh');
  });

  gn.on('disconnect', (reason) => {
    console.log('Disconnected:', reason);
  });

  // 3. Connect to the relay
  await gn.connect();

  // 4. Send a message to a peer
  await gn.send(PEER_ID, 'Hello from the mesh!');
  console.log('Message sent to', PEER_ID);

  // 5. Wait a moment for a reply, then disconnect
  setTimeout(() => {
    gn.disconnect();
    console.log('Done.');
  }, 5000);
}

main().catch(console.error);
