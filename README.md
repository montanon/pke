# PKE

Verifiable chain of custody for encrypted mobile evidence.

An iPhone-native application for creating encrypted mobile evidence snapshots with device signatures, nearby witness attestations, and selective disclosure.

## Repository structure

```
src/
  backend/     Python (FastAPI) — custody ledger, blob storage, registries
  ios/         Swift (SwiftUI) — capture, crypto, attestation, verification
  shared/      JSON Schema protocol definitions
context/       Public design docs, threat model, MVP scope
```

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (package manager)
- Docker (for local PostgreSQL)
- Xcode 15+ (for iOS development)

## Quick start

```bash
# Install dependencies
make install

# Start local database
make db

# Run linter, type checker, and tests
make ci

# Start backend dev server
make serve
```

## Available commands

```
make install    Install all dependencies + pre-commit hooks
make lint       Run ruff linter
make fmt        Format code with ruff
make typecheck  Run mypy strict type checking
make test       Run pytest
make ci         Run full CI checks locally
make db         Start local PostgreSQL via Docker
make serve      Run backend dev server
make clean      Remove caches and build artifacts
```

## Branching

- `main` — production. PRs require passing CI.
- `dev` — default development branch. PRs trigger CI but don't require it. Direct pushes allowed.
- `feature/*` — feature branches. PR to `dev`.

## Design context

See [`/context`](./context/README.md) for architecture, protocol overview, threat model, MVP scope, and more.

## License

MIT
