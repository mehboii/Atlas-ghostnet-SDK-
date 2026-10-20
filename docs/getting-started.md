# Getting Started

## Installation

```bash
npm install @n11x/atlas
```

Or install directly from GitHub:

```bash
npm install mehboii/ghostnet-SDK
```

## Requirements

- **Node.js** 18 or later
- **Browsers**: Any modern browser with WebSocket support
- **React Native**: Supported out of the box

## Quick Start

```ts
import { Atlas } from '@n11x/atlas';

// 1. Create client
const gn = new Atlas({ debug: true });

// 2. Create or restore identity
const identity = gn.createIdentity();
console.log('Your node ID:', identity.nodeId);
console.log('Back up your seed phrase:', identity.seedPhrase);

// 3. Connect to the mesh
await gn.connect();

// 4. Listen for messages
gn.on('message', (msg) => {
  console.log(`From ${msg.from}: ${msg.data}`);
});

// 5. Send a message
await gn.send('0x<peer-node-id>', 'Hello from the mesh!');

// 6. Disconnect when done
gn.disconnect();
```

## Restoring an Identity

The same seed phrase always produces the same identity. Use this to restore on a new device:

```ts
const gn = new Atlas();
const identity = gn.loadIdentity('your twelve word seed phrase goes here ...');
console.log(identity.nodeId); // same as the original
```

## CommonJS Usage

```js
const { Atlas } = require('@n11x/atlas');

const gn = new Atlas();
const identity = gn.createIdentity();
console.log(identity.nodeId);
```

## Next Steps

- [API Reference](./api-reference.md) — Full method documentation
- [Identity & Crypto](./identity-and-crypto.md) — How keys and encryption work
- [Error Handling](./error-handling.md) — Error types and recovery patterns
- [Security Model](./security.md) — Threat model and security guarantees
- [Examples](./examples.md) — Real-world usage patterns
