# PKE

Verifiable chain of custody for encrypted mobile evidence.

An iPhone-native application for creating encrypted mobile evidence snapshots with device signatures, nearby witness attestations, and selective disclosure. The system verifies custody signals, not objective truth.

## Architecture

```text
iOS App
  ├── Capture Service
  ├── Device Identity Service
  ├── Crypto Service
  ├── Attestation Service
  ├── Ledger Client
  ├── Key Grant Client
  └── Verification Service

Backend
  ├── API Service
  ├── Encrypted Blob Storage
  ├── Custody Ledger
  ├── Attestation Registry
  ├── Identity Registry
  ├── Key Grant Registry
  └── Report/Freeze Registry
```

The backend coordinates storage and retrieval but is not trusted with plaintext evidence, plaintext keys, or unverified custody claims. Clients verify cryptographic evidence locally.

## Protocol

The system defines five core protocol payloads and two metadata-level actions:

| Payload | Purpose |
|---------|---------|
| Snapshot Commitment | Binds a device identity to an encrypted snapshot hash |
| Witness Attestation | Nearby device signs the commitment without seeing content |
| Ledger Entry | Append-only hash-chained custody event record |
| Key Grant | Wraps per-snapshot key for an authorized recipient |
| Verification Report | Human-readable custody verification summary |
| Report | Metadata-level flag for review (no decryption required) |
| Freeze | Restricts future key grants for a reported snapshot |

Formal definitions in `src/shared/schemas/`. Protocol details in `context/04_protocol_overview.md`.

## Repository structure

```
src/
  backend/                Python (FastAPI) — custody ledger, blob storage, registries
    src/pke_backend/
      api/                API route handlers
      models/             SQLAlchemy ORM models
      schemas/            Pydantic request/response schemas
      services/           Business logic services
    tests/                pytest test suite
  ios/                    Swift (SwiftUI) — capture, crypto, attestation, verification
    PKE/
      App/                SwiftUI app entry
      Services/           Core service protocols
      Models/             Data models
      Views/              UI views
      Networking/         API client
    PKETests/
  shared/schemas/         JSON Schema protocol definitions (5 core schemas)
context/                  Public design docs, threat model, MVP scope (16 docs)
  assets/                 Mermaid architecture diagrams
  examples/               Synthetic JSON payload examples (7 files)
```

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (package manager)
- Docker (for local PostgreSQL)
- Xcode 15.4+ with the iOS 17 Simulator runtime (for iOS development)

## Quick start

```bash
# Install dependencies and pre-commit hooks
make install

# Start local database
make db

# Run linter, type checker, and tests
make ci

# Start backend dev server (requires running database and implemented main.py)
# make serve
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
make serve      Run backend dev server (port 8000, requires main.py)
make clean      Remove caches and build artifacts
make ios-test   Run iOS Swift Package library tests (`swift test`)
make ios-lint   Run SwiftLint on `src/ios/` sources
make ios-app-test  Build and test the PKE iOS app via xcodebuild + iOS Simulator
```

## iOS app

The iOS app target lives in `src/ios/PKE.xcodeproj`. Library code (crypto, identity, protocol, witness, HTTP client) is defined in `src/ios/Package.swift` and consumed by the Xcode project as a local SwiftPM package.

**Decision (HLAM-91):** the host app is hosted by an Xcode project, not an SPM-only package, because SwiftPM does not produce iOS application bundles. Library code stays in `Package.swift` to keep CI's `swift test` fast and Linux-friendly; the Xcode project links those products into the iOS app target.

**Local development**

```bash
# Open in Xcode (run ⌘R on an iOS 17+ simulator)
xed src/ios/PKE.xcodeproj

# Or run the same xcodebuild invocation CI uses
make ios-app-test
```

Requirements: macOS 14+, Xcode 15.4+ (defaults to the iOS 17 simulator runtime). Older Xcode versions fail with a deployment-target error.

## Development workflow

1. Copy `src/backend/.env.sample` to `src/backend/.env` and adjust values.
2. Run `make install` to install dependencies and set up pre-commit hooks.
3. Run `make db` to start PostgreSQL.
4. Run `make ci` before committing to catch lint, type, and test issues.

Pre-commit hooks run automatically on `git commit`: ruff lint + format, detect-secrets, trailing whitespace, and file checks.

Backend dependencies are managed via uv. From `src/backend/`:
- Add a runtime dependency: `uv add <package>`
- Add a dev dependency: `uv add --dev <package>`
- Sync after changes: `uv sync --dev --all-packages` (from repo root)

## Branching

- `main` — production. PRs require passing CI (lint, typecheck, test).
- `dev` — default development branch. PRs trigger CI but don't require it. Direct pushes allowed.
- `feature/*` — feature branches. PR to `dev`.

## Design context

The [`/context`](./context/README.md) directory contains 16 public-safe design documents covering architecture, protocol overview, threat model, privacy constraints, security assumptions, MVP scope, roadmap, demo scenarios, glossary, and implementation notes. All examples use synthetic placeholder values.

## Security

Report security issues privately. Do not submit sensitive material in public issues or pull requests. See [SECURITY.md](./SECURITY.md) and [context/14_security_reporting.md](./context/14_security_reporting.md).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, code style, branching, and PR expectations.

## License

MIT
