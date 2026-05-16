Run the full local CI pipeline for the pke project. Execute these steps in order and report results:

1. `make fmt` — auto-format code
2. `make lint` — ruff check (must pass with zero warnings)
3. `make typecheck` — mypy strict mode
4. `make test` — pytest suite

If any step fails, stop and report the failure with actionable fix suggestions. If all pass, confirm the branch is CI-ready.
