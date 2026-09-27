# Error Handling

All SDK errors extend the `GhostNetError` base class, which extends `Error`. Every error has a `code` property for programmatic matching.

```ts
import {
  GhostNetError,
  ConnectionError,
  IdentityError,
  EncryptionError,
  PeerNotFoundError,
} from '@n11x/atlas';
```

## Error Hierarchy

```
Error
└── GhostNetError          (code: string)
    ├── ConnectionError     (code: "ERR_CONNECTION")
    ├── IdentityError       (code: "ERR_IDENTITY")
    ├── EncryptionError     (code: "ERR_ENCRYPTION")
    └── PeerNotFoundError   (code: "ERR_PEER_NOT_FOUND", peerId: string)
```

## Error Types

### `GhostNetError`

Base class for all SDK errors.

| Property  | Type     | Description           |
| --------- | -------- | --------------------- |
| `message` | `string` | Human-readable error  |
| `code`    | `string` | Machine-readable code |

```ts
try {
  await gn.connect();
} catch (err) {
  if (err instanceof GhostNetError) {
    console.error(`[${err.code}] ${err.message}`);
  }
}
```

### `ConnectionError`

Thrown when WebSocket connection fails, is rejected, or when sending on a closed socket.

**Common causes:**
- No identity loaded before `connect()`
- Relay is unreachable
- Insecure `ws://` endpoint provided
- Sending while disconnected
- Message exceeds 64 KB size limit
- Max reconnect attempts (10) exhausted

```ts
gn.on('error', (err) => {
  if (err instanceof ConnectionError) {
    console.error('Connection problem:', err.message);
    // Maybe retry after a delay
  }
});
```

### `IdentityError`

Thrown when identity creation or restoration fails.

**Common causes:**
- Invalid BIP-39 seed phrase
- Wrong number of words
- Misspelled mnemonic word

```ts
try {
  gn.loadIdentity('invalid seed phrase');
} catch (err) {
  if (err instanceof IdentityError) {
    console.error('Bad seed phrase:', err.message);
  }
}
```

### `EncryptionError`

Thrown when message encryption or decryption fails.

**Common causes:**
- Corrupted ciphertext
- Tampered message (GCM auth tag mismatch)
- Wrong recipient key

```ts
gn.on('error', (err) => {
  if (err instanceof EncryptionError) {
    console.error('Crypto failure:', err.message);
  }
});
```

### `PeerNotFoundError`

Thrown when the relay reports that a peer is unknown or unreachable. Includes the `peerId` that wasn't found.

```ts
gn.on('error', (err) => {
  if (err instanceof PeerNotFoundError) {
    console.error(`Peer ${err.peerId} is offline`);
  }
});
```

## Recommended Error Handling Pattern

```ts
import { GhostNet, GhostNetError, ConnectionError, PeerNotFoundError } from '@n11x/atlas';

const gn = new GhostNet({ debug: true });

// Global error handler
gn.on('error', (err) => {
  if (err instanceof PeerNotFoundError) {
    showNotification(`${err.peerId} is offline`);
  } else if (err instanceof ConnectionError) {
    showNotification('Connection lost. Retrying...');
  } else {
    console.error('Unexpected error:', err);
  }
});

// Try/catch for async operations
async function sendMessage(peerId: string, text: string) {
  try {
    await gn.send(peerId, text);
  } catch (err) {
    if (err instanceof GhostNetError) {
      console.error(`Send failed [${err.code}]: ${err.message}`);
    }
    throw err;
  }
}
```
