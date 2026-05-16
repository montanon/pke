# PKE — Claude Code Instructions

## Project

Verifiable chain of custody for encrypted mobile evidence. See `/context` for full design docs.

## Stack

- **Backend**: Python 3.12+, FastAPI, SQLAlchemy async, PostgreSQL, uv
- **iOS**: Swift 5.9+, SwiftUI, CryptoKit, MultipeerConnectivity
- **Shared**: JSON Schema protocol definitions in `src/shared/schemas/`

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

Python uses ruff (30+ rule categories) and mypy strict mode. Config is in root `pyproject.toml`. Run `make ci` before committing.

iOS uses SwiftLint. Config in `src/ios/.swiftlint.yml`. `force_cast`, `force_try`, and `force_unwrapping` are errors.

## Branching

- `main` = production, CI required on PRs
- `dev` = default branch, CI triggers on PRs but not required, direct pushes allowed
- Feature branches PR into `dev`

## Security

- Never commit secrets, keys, certificates, or `.env` files
- Never store plaintext evidence or snapshot keys on the backend
- Use `src/backend/.env.sample` as template
- All crypto uses platform standard libraries — no custom primitives
