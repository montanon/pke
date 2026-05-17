# PKE — Claude Code Instructions

## Project

Verifiable chain of custody for encrypted mobile evidence. See `/context` for full design docs (16 files).

The project is in scaffolding stage. Backend Python packages contain empty `__init__.py` stubs. iOS directories are empty. No production code has been written yet.

## Stack

- **Backend**: Python 3.12+, FastAPI >=0.115, SQLAlchemy >=2.0 (async), asyncpg, Pydantic >=2.10, Alembic, uvicorn
- **iOS**: Swift 5.9+, SwiftUI, CryptoKit, MultipeerConnectivity
- **Database**: PostgreSQL 16 (Docker Compose for local dev)
- **Package manager**: uv (workspace mode)
- **Shared**: JSON Schema protocol definitions in `src/shared/schemas/`

## Repository structure

```
src/
  backend/
    pyproject.toml              Backend package config
    .env.sample                 Environment variable template
    alembic.ini                 Database migration config
    alembic/versions/           Migration scripts (empty)
    src/pke_backend/
      __init__.py               Package marker (empty)
      py.typed                  PEP 561 marker
      api/__init__.py           Route handlers (empty)
      models/__init__.py        SQLAlchemy models (empty)
      schemas/__init__.py       Pydantic schemas (empty)
      services/__init__.py      Business logic (empty)
    tests/__init__.py           Test suite (empty)
  ios/
    .swiftlint.yml              SwiftLint strict config
    PKE/{App,Services,Models,Views,Networking}/   (empty dirs)
    PKETests/                   (empty dir)
  shared/schemas/
    snapshot_commitment.json    JSON Schema
    witness_attestation.json    JSON Schema
    ledger_entry.json           JSON Schema (5 event types)
    key_grant.json              JSON Schema
    verification_report.json    JSON Schema
context/                        16 design docs + 7 examples + 2 diagrams
```

## Commands

- `make install` — install deps + pre-commit hooks
- `make lint` — ruff check
- `make fmt` — ruff format + fix
- `make typecheck` — mypy strict
- `make test` — pytest
- `make ci` — lint + typecheck + test
- `make db` — start local PostgreSQL
- `make serve` — uvicorn dev server on :8000

## Linting

Python uses ruff (30+ rule categories including bandit security checks) and mypy strict mode. All config is in root `pyproject.toml`. Run `make ci` before committing.

iOS uses SwiftLint. Config in `src/ios/.swiftlint.yml`. `force_cast`, `force_try`, and `force_unwrapping` are errors.

## Testing

- Test files go in `src/backend/tests/`
- pytest with `asyncio_mode = "auto"` and `strict_markers = true`
- `filterwarnings = ["error"]` — warnings are treated as errors
- CI test job runs against a PostgreSQL 16 service container
- Override database URL via `PKE_DATABASE_URL` environment variable

## Dependency management

- Root `pyproject.toml` defines the uv workspace with member `src/backend`
- Backend dependencies are in `src/backend/pyproject.toml`
- Add runtime deps: `uv add <package>` (from `src/backend/` directory)
- Add dev deps: `uv add --dev <package>`
- Sync after changes: `uv sync --dev --all-packages` (from repo root)

## Adding new backend functionality

- Route handlers → `src/backend/src/pke_backend/api/`
- Pydantic request/response schemas → `src/backend/src/pke_backend/schemas/`
- SQLAlchemy ORM models → `src/backend/src/pke_backend/models/`
- Business logic → `src/backend/src/pke_backend/services/`
- Protocol schemas → `src/shared/schemas/` (JSON Schema format)

## Branching

- `main` = production, CI required on PRs
- `dev` = default branch, CI triggers on PRs but not required, direct pushes allowed
- Feature branches PR into `dev`

## PR workflow

- Feature branches merge into `dev` via PR
- `dev` merges into `main` via PR (requires passing CI)
- CI runs 3 jobs: Lint & Format, Type Check, Test
- CI uses `astral-sh/setup-uv@v5` with caching enabled

## Protocol event types

The ledger tracks 5 custody event types: `SNAPSHOT_COMMITTED`, `WITNESS_ATTESTED`, `KEY_GRANTED`, `REPORTED`, `FROZEN`.

## Security

- Never commit secrets, keys, certificates, or `.env` files
- Never store plaintext evidence or snapshot keys on the backend
- Use `src/backend/.env.sample` as template
- All crypto uses platform standard libraries — no custom primitives
- Report security issues privately — see `context/14_security_reporting.md`
