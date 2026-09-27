# Security Model

## Threat Model

The Atlas SDK is designed to protect against:

| Threat                     | Protection                                          |
| -------------------------- | --------------------------------------------------- |
| Relay reads your messages  | E2E encryption — relay only sees ciphertext          |
| Network eavesdropping      | WSS (TLS) for transport + E2E encryption for payload |
| Message tampering          | AES-GCM authentication tag detects any modification  |
| Identity theft             | Ed25519 keypair derived from secret seed phrase      |
| Key reuse attacks          | Ephemeral X25519 keypair per message                 |
| Past message compromise    | Forward secrecy via ephemeral keys                   |
| Accidental key leak        | Private keys excluded from JSON serialization        |
| Insecure transport         | `ws://` endpoints rejected — `wss://` enforced       |
| Credential leak in URLs    | Embedded `user:pass@` in endpoint URLs rejected      |
| Memory exhaustion (DoS)    | 64 KB message size limit                             |
| Reconnect flood            | Max 10 reconnect attempts with exponential backoff   |

## What the SDK Does NOT Protect Against

| Threat                          | Why                                                  |
| ------------------------------- | ---------------------------------------------------- |
| Compromised device              | If the device is compromised, the private key is exposed |
| Lost seed phrase                | No recovery mechanism — the seed phrase IS the identity |
| Relay metadata analysis         | The relay knows who is online and who messages whom    |
| Replay attacks                  | No message sequence numbers at the crypto layer (transport responsibility) |
| Denial of service on the relay  | The relay can go offline — the SDK retries up to 10 times |

## Endpoint Validation

The SDK rejects:

- `ws://` — unencrypted WebSocket
- `http://` / `https://` — not a WebSocket protocol
- `javascript:` / `data:` — injection vectors
- URLs with embedded credentials (`wss://user:pass@host`)
- URLs with path traversal (`..`)
- Malformed URLs

```ts
// All of these throw ConnectionError:
new GhostNet({ endpoint: 'ws://insecure.com' });
new GhostNet({ endpoint: 'wss://user:pass@host.com' });
new GhostNet({ endpoint: 'wss://host.com/../../etc/passwd' });
new GhostNet({ endpoint: 'javascript:alert(1)' });
```

## Private Key Protection

The `Identity` object uses non-enumerable properties for sensitive fields:

```ts
const id = gn.createIdentity();

// Direct access works:
console.log(id.privateKey);  // "a1b2c3..."
console.log(id.seedPhrase);  // "abandon ability ..."

// But serialization is safe:
JSON.stringify(id);           // {"publicKey":"...","nodeId":"0x..."}
Object.keys(id);              // ["publicKey", "nodeId"]
console.log(id);              // { publicKey: '...', nodeId: '0x...' }
```

This prevents accidental exposure through logging, error reporters, or API calls.

## Dependency Audit

| Dependency        | Version | Audit Status | Purpose                    |
| ----------------- | ------- | ------------ | -------------------------- |
| `@noble/curves`   | ^1.8    | Audited      | Ed25519, X25519            |
| `@noble/hashes`   | ^1.7    | Audited      | BLAKE3, HKDF, SHA-256      |
| `@noble/ciphers`  | ^1.0    | Audited      | AES-256-GCM                |
| `bip39`           | ^3.1    | Widely used  | BIP-39 mnemonic generation |
| `ws`              | ^8.18   | Widely used  | WebSocket client for Node  |

Zero peer dependencies. The noble crypto libraries are independently audited by Cure53.

## Reporting Vulnerabilities

If you find a security issue, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers directly
3. Include steps to reproduce and potential impact

We take security seriously and will respond within 48 hours.
