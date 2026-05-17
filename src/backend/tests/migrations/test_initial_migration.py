"""Integration tests for migration 0001_create_ledger_entries (HLAM-56)."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from pke_backend.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"

EXPECTED_ENUM_LABELS = {
    "SNAPSHOT_COMMITTED",
    "WITNESS_ATTESTED",
    "KEY_GRANTED",
    "REPORTED",
    "FROZEN",
}

EXPECTED_INDEXES = {
    "ix_ledger_entries_snapshot_id",
    "ix_ledger_entries_event_type",
    "ix_ledger_entries_entry_timestamp",
}

EXPECTED_UNIQUE_CONSTRAINTS = {
    "uq_ledger_entries_ledger_entry_id",
    "uq_ledger_entries_entry_hash",
}

INSERT_SQL = text(
    "INSERT INTO ledger_entries "
    "(ledger_entry_id, event_type, snapshot_id, payload_hash, "
    "previous_entry_hash, entry_hash) "
    "VALUES (:ledger_entry_id, CAST(:event_type AS event_type), "
    ":snapshot_id, :payload_hash, :previous_entry_hash, :entry_hash) "
    "RETURNING id, entry_timestamp, version"
)


def _alembic_config() -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", get_settings().DATABASE_URL)
    return cfg


async def _alembic_upgrade(target: str = "head") -> None:
    await asyncio.to_thread(command.upgrade, _alembic_config(), target)


async def _alembic_downgrade(target: str = "base") -> None:
    await asyncio.to_thread(command.downgrade, _alembic_config(), target)


def _row(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ledger_entry_id": uuid.uuid4(),
        "event_type": "SNAPSHOT_COMMITTED",
        "snapshot_id": uuid.uuid4(),
        "payload_hash": b"\x11" * 32,
        "previous_entry_hash": None,
        "entry_hash": uuid.uuid4().bytes + uuid.uuid4().bytes,  # unique 32-byte
    }
    base.update(overrides)
    return base


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(get_settings().DATABASE_URL)
    try:
        async with eng.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        await eng.dispose()
        pytest.skip(f"postgres not reachable: {exc}")
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture(autouse=True)
async def _reset_db(engine: AsyncEngine) -> AsyncIterator[None]:
    await _alembic_downgrade()
    yield
    await _alembic_downgrade()


async def _table_names(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda c: sa_inspect(c).get_table_names())


async def _enum_labels(engine: AsyncEngine, name: str) -> list[str]:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT enumlabel FROM pg_enum e "
                "JOIN pg_type t ON t.oid = e.enumtypid "
                "WHERE t.typname = :name "
                "ORDER BY e.enumsortorder"
            ),
            {"name": name},
        )
        return [row[0] for row in result.all()]


# --- Tests ---------------------------------------------------------------


async def test_upgrade_creates_ledger_entries_table(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    assert "ledger_entries" in await _table_names(engine)


async def test_upgrade_creates_event_type_enum_with_five_labels(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    labels = await _enum_labels(engine, "event_type")
    assert set(labels) == EXPECTED_ENUM_LABELS
    assert len(labels) == 5


async def test_downgrade_drops_table_and_enum(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade()
    assert "ledger_entries" not in await _table_names(engine)
    assert await _enum_labels(engine, "event_type") == []


async def test_indexes_present_after_upgrade(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        indexes = await conn.run_sync(
            lambda c: sa_inspect(c).get_indexes("ledger_entries"),
        )
    names = {idx["name"] for idx in indexes}
    assert names >= EXPECTED_INDEXES


async def test_unique_constraints_present_after_upgrade(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        uqs = await conn.run_sync(
            lambda c: sa_inspect(c).get_unique_constraints("ledger_entries"),
        )
    names = {uq["name"] for uq in uqs}
    assert names >= EXPECTED_UNIQUE_CONSTRAINTS


async def test_previous_entry_hash_column_is_nullable(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda c: sa_inspect(c).get_columns("ledger_entries"),
        )
    previous = next(c for c in cols if c["name"] == "previous_entry_hash")
    assert previous["nullable"] is True


async def test_unique_entry_hash_enforced(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    shared_hash = b"\xaa" * 32
    async with engine.begin() as conn:
        await conn.execute(INSERT_SQL, _row(entry_hash=shared_hash))
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(INSERT_SQL, _row(entry_hash=shared_hash))


async def test_unique_ledger_entry_id_enforced(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    shared_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_SQL,
            _row(ledger_entry_id=shared_id, entry_hash=b"\x01" * 32),
        )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                INSERT_SQL,
                _row(ledger_entry_id=shared_id, entry_hash=b"\x02" * 32),
            )


async def test_genesis_row_with_null_previous_entry_hash_persists(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    async with engine.begin() as conn:
        result = await conn.execute(INSERT_SQL, _row(previous_entry_hash=None))
        inserted_id = result.one().id
    async with engine.connect() as conn:
        check = await conn.execute(
            text(
                "SELECT previous_entry_hash FROM ledger_entries WHERE id = :id",
            ),
            {"id": inserted_id},
        )
        assert check.scalar_one() is None


async def test_round_trip_upgrade_downgrade_upgrade(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade()
    await _alembic_upgrade()
    assert "ledger_entries" in await _table_names(engine)
    assert set(await _enum_labels(engine, "event_type")) == EXPECTED_ENUM_LABELS


async def test_double_upgrade_is_noop(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_upgrade()
    assert "ledger_entries" in await _table_names(engine)


async def test_server_defaults_populate_timestamp_and_version(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    async with engine.begin() as conn:
        result = await conn.execute(INSERT_SQL, _row())
        row = result.one()
    assert row.version == "0.1"
    assert row.entry_timestamp is not None
    now = datetime.now(tz=UTC)
    assert abs(row.entry_timestamp - now) < timedelta(seconds=5)


async def test_hash_columns_not_length_constrained_at_sql_level(
    engine: AsyncEngine,
) -> None:
    """SQL-level BYTEA accepts any length; 32-byte invariant is app-enforced."""
    await _alembic_upgrade()
    long_hash = b"\xff" * 64
    async with engine.begin() as conn:
        result = await conn.execute(
            INSERT_SQL,
            _row(payload_hash=long_hash, entry_hash=b"\x33" * 32),
        )
        inserted_id = result.one().id
    async with engine.connect() as conn:
        check = await conn.execute(
            text("SELECT LENGTH(payload_hash) FROM ledger_entries WHERE id = :id"),
            {"id": inserted_id},
        )
        assert check.scalar_one() == 64
