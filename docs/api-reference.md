# API Reference

## `Atlas` (also exported as `GhostNet`)

The main SDK client class. Manages identity, connection, and messaging.

```ts
import { Atlas } from '@n11x/atlas';
```

### Constructor

```ts
new Atlas(options?: AtlasOptions)
```

| Option     | Type      | Default                                        | Description                    |
| ---------- | --------- | ---------------------------------------------- | ------------------------------ |
| `endpoint` | `string`  | `wss://ghostnet-ji-production.up.railway.app`  | WebSocket relay URL (wss:// only) |
| `debug`    | `boolean` | `false`                                        | Enable debug logging to console |

**Throws** `ConnectionError` if endpoint is not `wss://`, contains credentials, or has path traversal sequences.

```ts
// Default — connects to production relay
const gn = new Atlas();

// Custom relay with debug logging
const gn = new Atlas({
  endpoint: 'wss://my-relay.example.com',
  debug: true,
});
```

---

## Identity Methods

### `createIdentity()`

Generate a brand-new identity with a fresh BIP-39 seed phrase.

```ts
createIdentity(): Identity
```

**Returns** an `Identity` object with `seedPhrase`, `publicKey`, `privateKey`, and `nodeId`.

> **Important**: The `seedPhrase` is the master secret. Back it up safely — it's the only way to restore this identity.

```ts
const identity = gn.createIdentity();
console.log(identity.nodeId);     // "0x7f3a..."
console.log(identity.seedPhrase); // "abandon ability able ..."
console.log(identity.publicKey);  // "a1b2c3..." (64 hex chars)
```

### `loadIdentity(seedPhrase)`

Restore an identity from an existing BIP-39 seed phrase.

```ts
loadIdentity(seedPhrase: string): Identity
```

| Parameter    | Type     | Description                    |
| ------------ | -------- | ------------------------------ |
| `seedPhrase` | `string` | A valid 12-word BIP-39 mnemonic |

**Returns** the same `Identity` every time for the same seed phrase.

**Throws** `IdentityError` if the seed phrase is invalid.

```ts
const identity = gn.loadIdentity('abandon ability able about above absent ...');
console.log(identity.nodeId); // deterministic — same as original
```

### `getIdentity()`

Get the currently loaded identity.

```ts
getIdentity(): Identity | null
```

**Returns** the current `Identity` or `null` if none has been created/loaded.

```ts
if (gn.getIdentity()) {
  console.log('Ready:', gn.getIdentity().nodeId);
}
```

---

## Connection Methods

### `connect()`

Connect to the GhostNet relay over WebSocket.

```ts
connect(): Promise<void>
```

**Throws** `ConnectionError` if no identity is loaded or the connection fails.

An identity must be created or loaded before calling `connect()`. The SDK automatically handles reconnection with exponential backoff (up to 10 attempts).

```ts
gn.createIdentity();
await gn.connect();
```

### `disconnect()`

Gracefully disconnect from the relay.

```ts
disconnect(): void
```

Safe to call even if not connected. Does not clear the identity — you can call `connect()` again without re-creating the identity.

```ts
gn.disconnect();
```

---

## Messaging Methods

### `send(peerId, message)`

Send an encrypted message to a peer by their node ID.

```ts
send(peerId: string, message: string): Promise<void>
```

| Parameter | Type     | Description                                  |
| --------- | -------- | -------------------------------------------- |
| `peerId`  | `string` | Recipient's node ID (`0x`-prefixed BLAKE3 hash) |
| `message` | `string` | The plaintext message (max 64 KB)             |

**Throws:**
- `ConnectionError` if not connected
- `ConnectionError` if message exceeds 64 KB
- `EncryptionError` if encryption fails

When the peer's public key is known (learned from the relay), messages are encrypted end-to-end using X25519 ECDH + AES-256-GCM. The relay cannot read encrypted messages.

```ts
await gn.send('0x7f3a...', 'Hello, private message!');
```

---

## Event Methods

### `on(event, handler)`

Subscribe to a GhostNet event.

```ts
on<K extends keyof GhostNetEvents>(event: K, handler: GhostNetEvents[K]): void
```

### `off(event, handler)`

Unsubscribe from a GhostNet event. Pass the same function reference used with `on()`.

```ts
off<K extends keyof GhostNetEvents>(event: K, handler: GhostNetEvents[K]): void
```

### Events

| Event          | Handler Signature                              | Description                        |
| -------------- | ---------------------------------------------- | ---------------------------------- |
| `message`      | `(msg: IncomingMessage) => void`               | Incoming message from a peer       |
| `error`        | `(err: Error) => void`                         | Connection, encryption, or relay error |
| `connect`      | `() => void`                                   | Successfully connected to relay    |
| `disconnect`   | `(reason: string) => void`                     | Disconnected from relay            |

```ts
// Listen for messages
gn.on('message', (msg) => {
  console.log(`From: ${msg.from}`);
  console.log(`Data: ${msg.data}`);
  console.log(`Time: ${new Date(msg.timestamp)}`);
});

// Handle errors
gn.on('error', (err) => {
  if (err instanceof PeerNotFoundError) {
    console.log('Peer offline:', err.peerId);
  } else {
    console.error('Error:', err.message);
  }
});

// Connection lifecycle
gn.on('connect', () => console.log('Connected'));
gn.on('disconnect', (reason) => console.log('Disconnected:', reason));

// Unsubscribe
const handler = (msg) => console.log(msg);
gn.on('message', handler);
gn.off('message', handler);
```

---

## Types

### `GhostNetOptions`

```ts
interface GhostNetOptions {
  endpoint?: string;   // WebSocket relay URL (default: production relay)
  debug?: boolean;     // Enable debug logging (default: false)
}
```

### `Identity`

```ts
interface Identity {
  seedPhrase: string;  // 12-word BIP-39 mnemonic (non-enumerable)
  publicKey: string;   // Hex-encoded Ed25519 public key (64 chars)
  privateKey: string;  // Hex-encoded Ed25519 private key (non-enumerable)
  nodeId: string;      // "0x" + BLAKE3 hash of public key
}
```

> **Security Note**: `seedPhrase` and `privateKey` are non-enumerable — they won't appear in `JSON.stringify()`, `console.log()`, or `Object.keys()`. They are still accessible as direct properties.

### `IncomingMessage`

```ts
interface IncomingMessage {
  from: string;        // Sender's node ID
  data: string;        // Decrypted message payload (UTF-8)
  timestamp: number;   // Milliseconds since epoch
}
```

### `GhostNetEvents`

```ts
interface GhostNetEvents {
  message: (msg: IncomingMessage) => void;
  error: (err: Error) => void;
  connect: () => void;
  disconnect: (reason: string) => void;
}
```
