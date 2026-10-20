# Contributing to @n11x/atlas

Thanks for your interest in contributing! This document covers the workflow and conventions we follow.

## Getting Started

```bash
git clone https://github.com/n11x/ghostnet-sdk.git
cd ghostnet-sdk
npm install
npm run build
npm test
```

### Prerequisites

- Node.js >= 18
- npm >= 9

## Development Workflow

```bash
npm run typecheck    # Type-check without emitting
npm run lint         # ESLint
npm run test         # Unit tests (vitest)
npm run test:integration  # Integration tests
npm run build        # Build with tsup
npm run release      # Full pipeline: typecheck → lint → test → build
```

## Branch Naming

Use the format `<type>/<short-description>`:

- `feat/bip39-identity` — new feature
- `fix/reconnect-loop` — bug fix
- `docs/api-reference` — documentation only
- `refactor/transport-cleanup` — internal changes
- `test/encryption-edge-cases` — tests only

## Commit Style

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add BIP-39 seed phrase identity creation
fix: prevent reconnect after intentional disconnect
docs: update quickstart example
test: add encryption roundtrip tests
chore: bump vitest to 3.x
```

Breaking changes use `!` after the type: `feat!: change Identity type shape`.

## Pull Request Checklist

Before opening a PR, ensure:

- [ ] `npm run release` passes (typecheck + lint + test + build)
- [ ] Tests added/updated for new functionality
- [ ] No secrets, `.env` files, or internal URLs committed
- [ ] `npm audit` shows no moderate+ vulnerabilities
- [ ] Documentation updated if public API changed
- [ ] Commit messages follow Conventional Commits

## Code Standards

- Strict TypeScript — no `any`, no `@ts-ignore` without inline justification
- Every public method needs a JSDoc block with an `@example`
- Keep runtime dependencies to 5 or fewer; justify new additions in the PR
- No telemetry, analytics, or phone-home behavior — privacy-first

## RFC Process for Breaking Changes

Breaking changes to the public API require an RFC before implementation:

1. Open a GitHub Issue titled `RFC: <description>`
2. Describe the current behavior, proposed change, and migration path
3. Allow at least 5 business days for discussion
4. Once approved, implement and include a migration guide in the PR

## Security Vulnerabilities

**Do NOT open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for reporting instructions.

## Questions?

Open an issue or reach out to the maintainers.
