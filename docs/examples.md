# Examples

## Basic: Create Identity and Connect

```ts
import { GhostNet } from '@n11x/atlas';

const gn = new GhostNet({ debug: true });

// Create a new identity
const identity = gn.createIdentity();
console.log('Node ID:', identity.nodeId);
console.log('Seed phrase (save this!):', identity.seedPhrase);

// Connect
await gn.connect();
console.log('Connected to GhostNet');

// Disconnect after 10 seconds
setTimeout(() => gn.disconnect(), 10_000);
```

## Restore Identity on a New Device

```ts
import { GhostNet } from '@n11x/atlas';

const gn = new GhostNet();

// Restore from saved seed phrase
const identity = gn.loadIdentity('your twelve word seed phrase goes right here ok thanks');
console.log('Restored node ID:', identity.nodeId);

await gn.connect();
```

## Send and Receive Messages

```ts
import { GhostNet } from '@n11x/atlas';

const gn = new GhostNet({ debug: true });
gn.createIdentity();

// Set up message handler BEFORE connecting
gn.on('message', (msg) => {
  console.log(`[${new Date(msg.timestamp).toLocaleTimeString()}] ${msg.from}: ${msg.data}`);
});

gn.on('error', (err) => {
  console.error('Error:', err.message);
});

await gn.connect();

// Send a message to a peer
const peerId = '0x7f3a...'; // get this from the other user
await gn.send(peerId, 'Hey, are you there?');
```

## Two-Node Chat

Run in two separate terminals to test messaging:

**Terminal 1 — Alice:**

```ts
import { GhostNet } from '@n11x/atlas';

const gn = new GhostNet({ debug: true });
const id = gn.createIdentity();
console.log('Alice node ID:', id.nodeId); // Share this with Bob

gn.on('message', (msg) => {
  console.log(`Bob says: ${msg.data}`);
});

await gn.connect();
console.log('Alice is online. Waiting for messages...');
```

**Terminal 2 — Bob:**

```ts
import { GhostNet } from '@n11x/atlas';

const ALICE_NODE_ID = '0x...'; // Paste Alice's node ID here

const gn = new GhostNet({ debug: true });
gn.createIdentity();
await gn.connect();

await gn.send(ALICE_NODE_ID, 'Hello Alice!');
console.log('Message sent!');
```

## Error Handling

```ts
import {
  GhostNet,
  ConnectionError,
  IdentityError,
  EncryptionError,
  PeerNotFoundError,
} from '@n11x/atlas';

const gn = new GhostNet();

// Handle invalid seed phrase
try {
  gn.loadIdentity('not a valid seed phrase');
} catch (err) {
  if (err instanceof IdentityError) {
    console.error('Invalid seed phrase');
  }
}

// Handle connection errors
gn.on('error', (err) => {
  if (err instanceof PeerNotFoundError) {
    console.log(`Peer ${err.peerId} is not online`);
  } else if (err instanceof ConnectionError) {
    console.log('Connection issue:', err.message);
  } else if (err instanceof EncryptionError) {
    console.log('Encryption failed:', err.message);
  }
});

// Handle send failures
gn.createIdentity();
await gn.connect();

try {
  await gn.send('0xnonexistent', 'hello');
} catch (err) {
  console.error('Send failed:', err.message);
}
```

## Express.js Integration

```ts
import express from 'express';
import { GhostNet } from '@n11x/atlas';

const app = express();
const gn = new GhostNet();

app.use(express.json());

// Initialize on server start
let nodeId: string;

async function init() {
  const identity = gn.createIdentity();
  nodeId = identity.nodeId;
  await gn.connect();

  gn.on('message', (msg) => {
    console.log('Received:', msg.from, msg.data);
  });
}

app.get('/node-id', (req, res) => {
  res.json({ nodeId });
});

app.post('/send', async (req, res) => {
  const { peerId, message } = req.body;
  try {
    await gn.send(peerId, message);
    res.json({ status: 'sent' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

init().then(() => {
  app.listen(3000, () => {
    console.log(`Server running. Node ID: ${nodeId}`);
  });
});
```

## React Hook

```tsx
import { useEffect, useRef, useState } from 'react';
import { GhostNet, IncomingMessage } from '@n11x/atlas';

function useGhostNet(seedPhrase?: string) {
  const gnRef = useRef<GhostNet | null>(null);
  const [connected, setConnected] = useState(false);
  const [nodeId, setNodeId] = useState<string | null>(null);
  const [messages, setMessages] = useState<IncomingMessage[]>([]);

  useEffect(() => {
    const gn = new GhostNet({ debug: true });
    gnRef.current = gn;

    const identity = seedPhrase
      ? gn.loadIdentity(seedPhrase)
      : gn.createIdentity();

    setNodeId(identity.nodeId);

    gn.on('message', (msg) => {
      setMessages((prev) => [...prev, msg]);
    });
    gn.on('connect', () => setConnected(true));
    gn.on('disconnect', () => setConnected(false));

    gn.connect().catch(console.error);

    return () => {
      gn.disconnect();
    };
  }, [seedPhrase]);

  const send = async (peerId: string, message: string) => {
    await gnRef.current?.send(peerId, message);
  };

  return { connected, nodeId, messages, send };
}

// Usage in a component:
function Chat({ peerId }: { peerId: string }) {
  const { connected, nodeId, messages, send } = useGhostNet();
  const [text, setText] = useState('');

  return (
    <div>
      <p>Node ID: {nodeId}</p>
      <p>Status: {connected ? 'Online' : 'Offline'}</p>

      {messages.map((msg, i) => (
        <div key={i}>{msg.from}: {msg.data}</div>
      ))}

      <input value={text} onChange={(e) => setText(e.target.value)} />
      <button onClick={() => { send(peerId, text); setText(''); }}>
        Send
      </button>
    </div>
  );
}
```
