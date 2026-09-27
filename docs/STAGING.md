# Staging / Local Relay Configuration

By default, the SDK connects to the production relay at `wss://ghostnet-ji-production.up.railway.app`. For development and testing, you should point the SDK at a staging or local relay to avoid hitting production.

## Using the `endpoint` Option

Pass a custom WebSocket URL when constructing the client:

```ts
import { GhostNet } from '@n11x/atlas';

const gn = new GhostNet({
  endpoint: 'wss://staging-relay.example.com',
  debug: true,
});
```

## Environment Variable Pattern

A common pattern is to read the endpoint from an environment variable:

```ts
const gn = new GhostNet({
  endpoint: process.env.GHOSTNET_RELAY_URL || undefined, // falls back to production default
  debug: process.env.NODE_ENV !== 'production',
});
```

Then set it per environment:

```bash
# .env.development
GHOSTNET_RELAY_URL=wss://staging-relay.example.com

# .env.test
GHOSTNET_RELAY_URL=wss://localhost:8080
```

## Local Relay for Testing

If you're running a local WebSocket relay for development:

```bash
# Start your local relay (not provided by this SDK)
# Then point the SDK at it:
GHOSTNET_RELAY_URL=wss://localhost:8080 npm test
```

## Requirements

- The endpoint **must** use `wss://` (TLS). The SDK rejects `ws://` endpoints.
- For local development with self-signed certificates, configure your Node.js environment to trust the certificate (e.g., `NODE_TLS_REJECT_UNAUTHORIZED=0` — **never in production**).
- The endpoint URL must not contain embedded credentials (`wss://user:pass@host` is rejected).

## Integration Tests

The integration test suite supports a custom relay via environment variable:

```bash
GHOSTNET_RELAY_URL=wss://staging-relay.example.com npm run test:integration
```

Tests that require a live relay are skipped by default and only run when `GHOSTNET_RELAY_URL` is set.
