# Atlas SDK (`@n11x/atlas`)

> **Architecture note:** This is a network SDK, not an AI SDK. The separate
> `@n11x/ghostnet-cli` Rust command runs a Node bridge that currently imports
> `@n11x/ghostnet-sdk`. Atlas uses the same GhostNet relay protocol.
> It does not expose a daemon, socket, or persisted identity for SDK clients
> to attach to. Both connect independently to a compatible WebSocket relay.

See [CLI integration](./docs/cli-integration.md) for installation, discovery,
identity loading, supported operations, security, and troubleshooting.

TypeScript SDK for integrating with the **GhostNet** encrypted mesh network.

Atlas implements a relay client compatible with the GhostNet CLI. It provides
identity derivation, signed encrypted messages, and WebSocket transport.

**Runtime:** Node.js 18+. A browser bundle is built, but browser and React Native
network integration are not verified by the Node test suite.

## Install

```bash
npm install @n11x/atlas
```

For the separate CLI, run `npm install -g @n11x/ghostnet-cli`, then
`ghostnet setup` and `ghostnet identity create`. Save the printed phrase
privately. The CLI and SDK need the same phrase and relay URL to use the same
network identity. The CLI never stores a default phrase for the SDK to read.

## Quickstart

```ts
import { Atlas } from '@n11x/atlas';

const gn = new Atlas({ debug: true });

// Explicitly restore the same identity used by the CLI.
const identity = gn.loadIdentity(process.env.GHOSTNET_SEED!);
console.log('Node ID:', identity.nodeId);
// Keep the seed phrase private; the CLI does not save a default identity.

// Connect to the mesh
await gn.connect();

// Listen for messages
gn.on('message', (msg) => {
  console.log(`${msg.from}: ${msg.data}`);
});

// Send an encrypted message to a peer
const peer = gn.addPeer(process.env.GHOSTNET_PEER_PUBLIC_KEY!);
await gn.send(peer.nodeId, 'hello from the mesh!');

// Disconnect when done
gn.disconnect();
```

The recipient public key must be confirmed through a trusted channel before
calling `addPeer`. Alternatively, the SDK learns a key from a signed peer
announcement or message. `listPeers()` reports keys known in this process;
it is not an online directory. `getStatus()` reports local WebSocket state.
`send()` confirms a WebSocket write; this relay protocol has no delivery receipt.
`getPublicIdentity()` is safe for display, while `getIdentity()` includes secrets.
Use `subscribe(event, handler)` for a cleanup function or `on`/`off` for manual
subscription management. A connection error or `PeerNotFoundError` indicates a
missing relay connection or recipient key, respectively.
`requireEncryption` defaults to `true`; setting it to `false` explicitly
allows signed plaintext fallback and should not be used for sensitive data.
The relay can observe routing metadata. The SDK adds no telemetry or AI APIs.
`GhostNet` remains an export alias for existing application code.

Node consumers can call `inspectCli()` from `@n11x/atlas/cli`, or pass
an explicit executable path. It discovers the native CLI, checks its version
against the verified 0.2.x line, and reports whether `ghostnet setup` installed
the bridge. The CLI is optional for direct SDK use and is never installed or
launched automatically by this package. There is no local CLI daemon or IPC.

## Documentation

| Guide | Description |
| --- | --- |
| [Getting Started](./docs/getting-started.md) | Installation, quickstart, and first steps |
| [API Reference](./docs/api-reference.md) | Full method and type documentation |
| [Identity & Crypto](./docs/identity-and-crypto.md) | How keys, encryption, and identity work |
| [Error Handling](./docs/error-handling.md) | Error types, codes, and recovery patterns |
| [Security Model](./docs/security.md) | Threat model, guarantees, and limitations |
| [Examples](./docs/examples.md) | Node.js, Express, React, and two-node chat |

## API

### `new Atlas(options?)`

| Option     | Type      | Default                            | Description             |
| ---------- | --------- | ---------------------------------- | ----------------------- |
| `endpoint` | `string`  | `wss://ghostnet-ji-production...`  | WebSocket relay URL (wss:// only) |
| `debug`    | `boolean` | `false`                            | Enable console logging  |

### Identity

| Method                        | Returns    | Description                              |
| ----------------------------- | ---------- | ---------------------------------------- |
| `.createIdentity()`           | `Identity` | Generate a new BIP-39 identity           |
| `.loadIdentity(seedPhrase)`   | `Identity` | Restore identity from a 12-word mnemonic |
| `.getIdentity()`              | `Identity \| null` | Current identity                  |
| `.getPublicIdentity()`        | Public identity or null | Public node ID and key |
| `.addPeer(publicKey)`         | `PeerInfo` | Register a verified recipient key |
| `.listPeers()`                | `PeerInfo[]` | Locally known peer keys |

### Connection

| Method          | Returns         | Description                  |
| --------------- | --------------- | ---------------------------- |
| `.connect()`    | `Promise<void>` | Connect to the mesh relay    |
| `.disconnect()`  | `void`          | Gracefully disconnect        |
| `.getStatus()`   | `NetworkStatus` | Local connection state       |

### Messaging

| Method                    | Returns         | Description                        |
| ------------------------- | --------------- | ---------------------------------- |
| `.send(peerId, message)`  | `Promise<void>` | Send encrypted message to a peer (max 64 KB) |

### Events

| Event          | Payload                                  | Description            |
| -------------- | ---------------------------------------- | ---------------------- |
| `message`      | `{ from: string, data: string, timestamp: number }` | Incoming message |
| `error`        | `Error`                                  | Connection/crypto error|
| `connect`      | —                                        | Connected to relay     |
| `disconnect`   | `string` (reason)                        | Disconnected           |

### Errors

All errors extend `GhostNetError` (which extends `Error`):

- `ConnectionError` — WebSocket connection failures
- `IdentityError` — invalid seed phrase or key derivation failure
- `EncryptionError` — encrypt/decrypt failures
- `PeerNotFoundError` — unknown or unreachable peer (includes `.peerId`)
- `PeerVerificationError` — invalid recipient or public key
- `PayloadTooLargeError` — message exceeds 64 KiB

## Crypto Scheme

| Primitive         | Algorithm                        |
| ----------------- | -------------------------------- |
| Identity key      | Ed25519 (from BIP-39 seed)       |
| Node ID           | BLAKE3 hash of public key        |
| Key exchange      | X25519 ECDH (ephemeral keypair)  |
| Key derivation    | HKDF-SHA256                      |
| Message encryption| AES-256-GCM                      |

All crypto primitives use audited [noble](https://paulmillr.com/noble/) libraries (Cure53 audit).

## Dependencies

| Package           | Why                                                    |
| ----------------- | ------------------------------------------------------ |
| `@noble/ciphers`  | AES-256-GCM — audited, pure JS, cross-platform         |
| `@noble/curves`   | Ed25519 + X25519 — audited, zero-dep, cross-platform   |
| `@noble/hashes`   | BLAKE3, HKDF, SHA-256 — same family, audited           |
| `bip39`           | BIP-39 mnemonic generation and validation              |
| `ws`              | WebSocket client for Node.js (browsers use native WS)  |

5 runtime deps. Zero peer deps.

## Security

- E2E encrypted messaging (X25519 + AES-256-GCM)
- Ephemeral sender keys per encrypted message; compromise of a recipient's
  static identity key may still expose recorded past ciphertexts
- Private keys excluded from JSON serialization
- `wss://` enforced — insecure endpoints rejected
- No telemetry, no analytics, no phone-home
- 64 KB message size limit
- See [Security Model](./docs/security.md) for full details

## Roadmap

The following features are planned for future releases:

- **v0.2** — GhostNet Pay (micropayments over the mesh)
- **v0.2** — Ghost Radar (peer discovery)
- **v0.2** — Ghost Shield cloaking
- **v0.3** — Ghost Cards (portable identity cards)
- **v0.3** — Proximity Connect (local mesh via BLE/mDNS)

## License

[MIT](./LICENSE) — N11X Collective

