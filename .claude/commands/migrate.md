Help create and apply Alembic database migrations for pke.

If $ARGUMENTS contains a migration description:
1. Ensure the local database is running (`make db`)
2. Generate a new migration: `uv run alembic revision --autogenerate -m "$ARGUMENTS"`
3. Read the generated migration file and review it for correctness
4. If the migration looks safe, apply it: `uv run alembic upgrade head`
5. Report what changed

If no arguments provided:
1. Show current migration state: `uv run alembic current`
2. Show migration history: `uv run alembic history`
3. Ask what migration the user wants to create
