# Contributing

PKE is a prototype for verifiable chain of custody for encrypted mobile evidence. Contributions are welcome.

## Getting started

See the [README](./README.md) for prerequisites and quick start.

## Development setup

1. Clone the repository and check out the `dev` branch.
2. Copy `src/backend/.env.sample` to `src/backend/.env` and adjust values.
3. Run `make install` to install dependencies and pre-commit hooks.
4. Run `make db` to start the local PostgreSQL database.
5. Run `make ci` to verify everything works.

## Code style

### Python

- Linter and formatter: **ruff** (30+ rule categories, strict config in `pyproject.toml`).
- Type checker: **mypy** in strict mode.
- Run `make ci` before committing. Pre-commit hooks enforce formatting automatically.
- Line length: 120 characters.
- Quote style: double quotes.

### Swift

- Linter: **SwiftLint** (config in `src/ios/.swiftlint.yml`).
- `force_cast`, `force_try`, and `force_unwrapping` are errors.
- Line length: warning at 120, error at 150.

## Branching and pull requests

- Create feature branches from `dev`.
- Open PRs targeting `dev`.
- PRs to `dev` trigger CI but do not require it to pass. Direct pushes to `dev` are allowed.
- PRs to `main` (production) require all CI checks to pass: Lint & Format, Type Check, Test.
- Keep PRs focused. One concern per PR.

## Commit messages

- Use imperative mood ("Add endpoint" not "Added endpoint").
- Keep the first line under 72 characters.
- Reference relevant context docs if the change affects protocol or architecture.

## Testing

- Add tests for new features. Tests go in `src/backend/tests/`.
- Use pytest with async support (`asyncio_mode = "auto"`).
- CI runs tests against a PostgreSQL 16 service container.

## Documentation

- Update relevant docs in `/context` when changing protocol or architecture.
- Keep examples synthetic — use `_test_` prefixed placeholder values.
- Update `context/MANIFEST.json` if adding or removing context files.

## Security

Do not submit security issues in public issues or pull requests. See [SECURITY.md](./SECURITY.md) and [context/14_security_reporting.md](./context/14_security_reporting.md).

## Publication safety

Never commit real media, PII, secrets, keys, certificates, or production credentials. Review [context/13_publication_checklist.md](./context/13_publication_checklist.md) before publishing.
