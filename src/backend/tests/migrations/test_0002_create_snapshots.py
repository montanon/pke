"""Integration tests for migration 0002_create_snapshots (HLAM-61)."""

from __future__ import annotations

import asyncio
import json
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

EXPECTED_COLUMNS: dict[str, bool] = {
    "snapshot_id": False,
    "ciphertext_hash": False,
    "owner_signing_public_key": False,
    "owner_encryption_public_key": False,
    "capture_timestamp": False,
    "metadata_policy": False,
    "session_nonce": False,
    "owner_signature": False,
    "version": False,
    "blob_storage_uri": False,
    "created_at": False,
}

EXPECTED_EXPLICIT_INDEXES = {
    "ix_snapshots_owner_signing_public_key",
    "ix_snapshots_created_at",
}

EXPECTED_UNIQUE_CONSTRAINTS = {"uq_snapshots_owner_pk_session_nonce"}

INSERT_SQL = text(
    "INSERT INTO snapshots ("
    "snapshot_id, ciphertext_hash, owner_signing_public_key, "
    "owner_encryption_public_key, capture_timestamp, metadata_policy, "
    "session_nonce, owner_signature, blob_storage_uri"
    ") VALUES ("
    ":snapshot_id, :ciphertext_hash, :owner_signing_public_key, "
    ":owner_encryption_public_key, :capture_timestamp, "
    "CAST(:metadata_policy AS JSONB), :session_nonce, :owner_signature, "
    ":blob_storage_uri"
    ") RETURNING snapshot_id, version, created_at, metadata_policy"
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
        "snapshot_id": uuid.uuid4(),
        "ciphertext_hash": b"\x11" * 32,
        "owner_signing_public_key": b"\x22" * 33,
        "owner_encryption_public_key": b"\x33" * 33,
        "capture_timestamp": datetime.now(tz=UTC),
        "metadata_policy": json.dumps(
            {
                "location_public": False,
                "location_precision": "city",
                "media_type": "photo",
            }
        ),
        "session_nonce": b"\x44" * 16,
        "owner_signature": b"\x55" * 64,
        "blob_storage_uri": "blob://example/snap_test_001",
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


# --- Tests ---------------------------------------------------------------


async def test_upgrade_creates_snapshots_table(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    assert "snapshots" in await _table_names(engine)


async def test_snapshot_columns_match_spec(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda c: sa_inspect(c).get_columns("snapshots"),
        )
    by_name = {c["name"]: c for c in cols}
    assert set(by_name.keys()) == set(EXPECTED_COLUMNS.keys())
    for name, nullable in EXPECTED_COLUMNS.items():
        assert by_name[name]["nullable"] is nullable, f"{name} nullability mismatch"
    assert by_name["created_at"]["default"] is not None
    assert by_name["version"]["default"] is not None


async def test_snapshot_id_is_primary_key_at_sql_level(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        pk = await conn.run_sync(
            lambda c: sa_inspect(c).get_pk_constraint("snapshots"),
        )
    assert pk["constrained_columns"] == ["snapshot_id"]


async def test_indexes_present_after_upgrade(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        indexes = await conn.run_sync(
            lambda c: sa_inspect(c).get_indexes("snapshots"),
        )
    names = {idx["name"] for idx in indexes}
    assert names >= EXPECTED_EXPLICIT_INDEXES


async def test_unique_constraints_present_after_upgrade(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        uqs = await conn.run_sync(
            lambda c: sa_inspect(c).get_unique_constraints("snapshots"),
        )
    by_name = {uq["name"]: uq for uq in uqs}
    assert set(by_name.keys()) >= EXPECTED_UNIQUE_CONSTRAINTS
    composite = by_name["uq_snapshots_owner_pk_session_nonce"]
    assert composite["column_names"] == [
        "owner_signing_public_key",
        "session_nonce",
    ]


async def test_unique_owner_pk_session_nonce_enforced(
    engine: AsyncEngine,
) -> None:
    """AC #3: replay via reused (owner_pk, session_nonce) is DB-rejected."""
    await _alembic_upgrade()
    owner_pk = b"\xaa" * 33
    nonce = b"\xbb" * 16
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_SQL,
            _row(owner_signing_public_key=owner_pk, session_nonce=nonce),
        )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                INSERT_SQL,
                _row(
                    snapshot_id=uuid.uuid4(),
                    owner_signing_public_key=owner_pk,
                    session_nonce=nonce,
                ),
            )


async def test_unique_owner_pk_session_nonce_allows_different_owner(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    nonce = b"\xcc" * 16
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_SQL,
            _row(owner_signing_public_key=b"\xaa" * 33, session_nonce=nonce),
        )
        await conn.execute(
            INSERT_SQL,
            _row(owner_signing_public_key=b"\xbb" * 33, session_nonce=nonce),
        )


async def test_unique_owner_pk_session_nonce_allows_different_nonce(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    owner_pk = b"\xdd" * 33
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_SQL,
            _row(owner_signing_public_key=owner_pk, session_nonce=b"\x01" * 16),
        )
        await conn.execute(
            INSERT_SQL,
            _row(owner_signing_public_key=owner_pk, session_nonce=b"\x02" * 16),
        )


async def test_downgrade_drops_snapshots_table(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade()
    tables = await _table_names(engine)
    assert "snapshots" not in tables
    assert "ledger_entries" not in tables


async def test_round_trip_upgrade_downgrade_upgrade(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade()
    await _alembic_upgrade()
    tables = await _table_names(engine)
    assert "snapshots" in tables
    assert "ledger_entries" in tables


async def test_double_upgrade_is_noop(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_upgrade()
    assert "snapshots" in await _table_names(engine)


async def test_server_defaults_populate_created_at_and_version(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    async with engine.begin() as conn:
        result = await conn.execute(INSERT_SQL, _row())
        row = result.one()
    assert row.version == "0.1"
    assert row.created_at is not None
    created_at = row.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    assert abs(created_at - datetime.now(tz=UTC)) < timedelta(seconds=5)


async def test_metadata_policy_jsonb_round_trips_losslessly(
    engine: AsyncEngine,
) -> None:
    """AC #6: full-shape metadata_policy survives a round-trip unchanged."""
    await _alembic_upgrade()
    payload = {
        "location_public": False,
        "location_precision": "city",
        "media_type": "photo",
    }
    async with engine.begin() as conn:
        result = await conn.execute(
            INSERT_SQL,
            _row(metadata_policy=json.dumps(payload)),
        )
        row = result.one()
    assert row.metadata_policy == payload


async def test_metadata_policy_jsonb_accepts_optional_location_precision(
    engine: AsyncEngine,
) -> None:
    """AC #6 edge: location_precision is optional in the JSONB shape."""
    await _alembic_upgrade()
    payload = {"location_public": True, "media_type": "video"}
    async with engine.begin() as conn:
        result = await conn.execute(
            INSERT_SQL,
            _row(metadata_policy=json.dumps(payload)),
        )
        row = result.one()
    assert row.metadata_policy == payload
    assert "location_precision" not in row.metadata_policy


async def test_chain_to_migration_0001(engine: AsyncEngine) -> None:
    """Upgrading from base materializes both 0001 and 0002 tables."""
    await _alembic_upgrade()
    tables = set(await _table_names(engine))
    assert {"ledger_entries", "snapshots"} <= tables


async def test_capture_timestamp_accepts_far_future(engine: AsyncEngine) -> None:
    """Edge E4: device-reported far-future capture_timestamp is stored as-is."""
    await _alembic_upgrade()
    far_future = datetime(2099, 12, 31, 23, 59, 59, tzinfo=UTC)
    inserted_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_SQL,
            _row(snapshot_id=inserted_id, capture_timestamp=far_future),
        )
    async with engine.connect() as conn:
        check = await conn.execute(
            text(
                "SELECT capture_timestamp FROM snapshots WHERE snapshot_id = :id",
            ),
            {"id": inserted_id},
        )
        stored = check.scalar_one()
    if stored.tzinfo is None:
        stored = stored.replace(tzinfo=UTC)
    assert stored == far_future
