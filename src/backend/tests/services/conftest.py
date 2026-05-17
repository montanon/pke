from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.config import get_settings
from pke_backend.db import dispose_engine, get_engine, get_sessionmaker
from pke_backend.models import (
    CIPHERTEXT_HASH_BYTES,
    SESSION_NONCE_BYTES,
    SNAPSHOT_VERSION,
    Snapshot,
)

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _BACKEND_DIR / "alembic.ini"

_HLAM79_TABLES = (
    "freezes",
    "reports",
    "ledger_entries",
    "snapshots",
)


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
    async with sm() as s:
        yield s


@pytest.fixture
async def hlam79_clean() -> AsyncIterator[None]:
    """Reset all HLAM-79-touched tables (freezes, reports, ledger, snapshots).

    Wider than :func:`clean_ledger` because the reports + freezes services
    write into ``snapshots`` (via FK), ``reports``, ``freezes``, and
    ``ledger_entries`` — all four need to start empty for the per-test
    isolation that the HLAM-79 service suite relies on.
    """
    await dispose_engine()
    await _probe_or_skip()
    await _ensure_head()
    sm = get_sessionmaker()
    async with sm() as s:
        await s.execute(
            text(f"TRUNCATE TABLE {', '.join(_HLAM79_TABLES)} RESTART IDENTITY CASCADE"),
        )
        await s.commit()
    yield
    await dispose_engine()


@pytest.fixture
async def session(hlam79_clean: None) -> AsyncIterator[AsyncSession]:
    """Fresh ``AsyncSession`` against the HLAM-79-clean schema.

    Provided as ``session`` (rather than ``db_session``) for the reports +
    freezes + snapshots tests because they touch more than just the ledger.
    """
    sm = get_sessionmaker()
    async with sm() as s:
        yield s


@pytest.fixture
async def seed_snapshot(session: AsyncSession) -> uuid.UUID:
    """Insert a minimal :class:`Snapshot` row and return its ``snapshot_id``.

    Used by the report/freeze service tests that need a snapshot to attach to.
    The owner key material is synthetic; tests that need a real keypair
    should build their own and link to a snapshot they seed via this helper.
    """
    snapshot_id = uuid.uuid4()
    snapshot = Snapshot(
        snapshot_id=snapshot_id,
        ciphertext_hash=b"\x11" * CIPHERTEXT_HASH_BYTES,
        owner_signing_public_key=b"\x04" + b"\x22" * 64,
        owner_encryption_public_key=b"\x04" + b"\x33" * 64,
        capture_timestamp=datetime.now(tz=UTC),
        metadata_policy={"location_public": False, "media_type": "photo"},
        session_nonce=b"\x44" * SESSION_NONCE_BYTES,
        owner_signature=b"\x55" * 64,
        version=SNAPSHOT_VERSION,
        blob_storage_uri="s3://test/bucket/snapshot",
    )
    session.add(snapshot)
    await session.commit()
    return snapshot_id
