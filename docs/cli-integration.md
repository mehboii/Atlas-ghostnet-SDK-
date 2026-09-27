# CLI and SDK integration

The `@n11x/ghostnet-cli` package exposes the `ghostnet` command. `ghostnet setup` installs its Node bridge at `~/.ghostnet-cli/bridge`; the current CLI bridge imports `@n11x/ghostnet-sdk`. Atlas is a separate package with the same GhostNet relay protocol. `ghostnet identity create` prints a BIP-39 phrase. `ghostnet identity load` checks a phrase for that command only. `ghostnet send` and `ghostnet listen` use `GHOSTNET_SEED` or `--seed` to load an identity for their own process. A CLI process is not an attachable node. Atlas connects directly to the compatible relay using the same phrase.

```sh
npm install -g @n11x/ghostnet-cli
ghostnet setup
ghostnet identity create
```

The SDK must explicitly restore the identity:

```ts
import { Atlas } from '@n11x/atlas';
import { inspectCli } from '@n11x/atlas/cli';

const cli = await inspectCli();
if (cli.available && !cli.compatible) throw new Error(cli.detail);

const gn = new Atlas();
gn.loadIdentity(process.env.GHOSTNET_SEED!);
const stop = gn.subscribe('message', (message) => console.log(message.from, message.data));
try {
  await gn.connect();
  console.log(gn.getPublicIdentity(), gn.getStatus(), gn.listPeers());
  const peer = gn.addPeer(process.env.GHOSTNET_PEER_PUBLIC_KEY!);
  await gn.send(peer.nodeId, 'hello');
} finally {
  stop();
  gn.disconnect();
}
```

`inspectCli(cliPath?)` is a Node-only export. It searches `PATH` or uses the explicit path, resolves npm shims to the native binary, invokes only `--version` with a timeout, checks the CLI 0.2.x line, and reports whether the documented bridge install exists. It never invokes `setup` or starts a CLI listener. A missing CLI is normal for a standalone SDK user.

Peer lists contain locally known public keys, learned from a valid signed message or announcement or supplied through `addPeer`. They are not an online peer directory. `send()` confirms a WebSocket write, not delivery. The repository defines no acknowledgment, remote node administration, Argon2id identity store, or local IPC protocol. Verify recipient public keys through a trusted channel before adding them.

The SDK uses Ed25519 signatures, BLAKE3 node IDs, ephemeral X25519, HKDF-SHA256, and AES-256-GCM. `requireEncryption` defaults to true. The relay sees routing metadata. No SDK telemetry is enabled. `getIdentity()` is secret-bearing for compatibility; prefer `getPublicIdentity()` for display and logs.
