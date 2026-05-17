from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.config import get_settings
from pke_backend.db import dispose_engine, get_engine, get_sessionmaker

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _BACKEND_DIR / "alembic.ini"


def _alembic_config() -> Config:
    cfg = Config(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", get_settings().DATABASE_URL)
    return cfg


async def _ensure_head() -> None:
    """Bring the schema up to ``head``.

    Migration tests downgrade to base between runs; without this, services
    tests run against an empty database. Using ``asyncio.to_thread`` because
    alembic's command API is synchronous.
    """
    await asyncio.to_thread(command.upgrade, _alembic_config(), "head")


async def _probe_or_skip() -> None:
    engine = get_engine()
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await dispose_engine()
        pytest.skip(f"postgres not reachable: {exc}")


@pytest.fixture
async def clean_ledger() -> AsyncIterator[None]:
    """Truncate ledger_entries before the test; dispose the engine afterwards.

    Ensures the schema is at ``head`` (migration tests may have left it at
    ``base``), then truncates the ledger so the test starts on an empty chain.
    Tests that need a session create one via
    :func:`pke_backend.db.get_sessionmaker`.
    """
    await dispose_engine()
    await _probe_or_skip()
    await _ensure_head()
    sm = get_sessionmaker()
    async with sm() as session:
        await session.execute(text("TRUNCATE TABLE ledger_entries RESTART IDENTITY"))
        await session.commit()
    yield
    await dispose_engine()


@pytest.fixture
async def db_session(clean_ledger: None) -> AsyncIterator[AsyncSession]:
    """Yield one AsyncSession against the truncated ledger table."""
    sm = get_sessionmaker()
    async with sm() as session:
        yield session
