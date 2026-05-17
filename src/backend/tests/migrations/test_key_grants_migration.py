"""Integration tests for migration 0005_create_key_grants (HLAM-72)."""

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
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from pke_backend.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"

EXPECTED_COLUMNS = {
    "id",
    "grant_id",
    "snapshot_id",
    "recipient_encryption_public_key",
    "wrapped_snapshot_key",
    "wrapping_algorithm",
    "granted_by_signing_public_key",
    "grant_timestamp",
    "grant_signature",
    "version",
    "created_at",
}

EXPECTED_INDEXES = {
    "ix_key_grants_snapshot_id",
    "ix_key_grants_recipient_encryption_public_key",
}

EXPECTED_UNIQUE_CONSTRAINTS = {
    "uq_key_grants_grant_id",
    "uq_key_grants_snapshot_recipient",
}

SNAPSHOT_INSERT_SQL = text(
    "INSERT INTO snapshots ("
    "snapshot_id, ciphertext_hash, owner_signing_public_key, "
    "owner_encryption_public_key, capture_timestamp, metadata_policy, "
    "session_nonce, owner_signature, blob_storage_uri"
    ") VALUES ("
    ":snapshot_id, :ciphertext_hash, :owner_signing_public_key, "
    ":owner_encryption_public_key, :capture_timestamp, "
    "CAST(:metadata_policy AS JSONB), :session_nonce, :owner_signature, "
    ":blob_storage_uri"
    ") RETURNING snapshot_id"
)

INSERT_SQL = text(
    "INSERT INTO key_grants "
    "(grant_id, snapshot_id, recipient_encryption_public_key, "
    "wrapped_snapshot_key, wrapping_algorithm, "
    "granted_by_signing_public_key, grant_timestamp, grant_signature) "
    "VALUES (:grant_id, :snapshot_id, :recipient_encryption_public_key, "
    ":wrapped_snapshot_key, :wrapping_algorithm, "
    ":granted_by_signing_public_key, :grant_timestamp, :grant_signature) "
    "RETURNING id, created_at, version"
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


def _snapshot_row(**overrides: object) -> dict[str, object]:
    """Build a snapshot row payload that satisfies the snapshots NOT NULL set.

    Each call produces a unique ``(owner_signing_public_key, session_nonce)``
    pair so multiple snapshots can coexist in the same test without hitting the
    replay-protection UNIQUE.
    """
    nonce_seed = uuid.uuid4().bytes
    owner_seed = uuid.uuid4().bytes + uuid.uuid4().bytes
    base: dict[str, object] = {
        "snapshot_id": uuid.uuid4(),
        "ciphertext_hash": b"\xaa" * 32,
        "owner_signing_public_key": owner_seed[:33],
        "owner_encryption_public_key": b"\xbb" * 33,
        "capture_timestamp": datetime.now(tz=UTC),
        "metadata_policy": json.dumps({"location_public": False}),
        "session_nonce": nonce_seed[:16],
        "owner_signature": b"\xcc" * 64,
        "blob_storage_uri": "blob://example/test",
    }
    base.update(overrides)
    return base


async def _insert_snapshot(conn: AsyncConnection, **overrides: object) -> uuid.UUID:
    payload = _snapshot_row(**overrides)
    result = await conn.execute(SNAPSHOT_INSERT_SQL, payload)
    return uuid.UUID(str(result.scalar_one()))


def _row(snapshot_id: uuid.UUID, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "grant_id": uuid.uuid4(),
        "snapshot_id": snapshot_id,
        "recipient_encryption_public_key": f"recipient_{uuid.uuid4().hex}",
        "wrapped_snapshot_key": b"\x11" * 60,
        "wrapping_algorithm": "ecdhp256+aesgcm256",
        "granted_by_signing_public_key": f"owner_{uuid.uuid4().hex}",
        "grant_timestamp": datetime.now(tz=UTC),
        "grant_signature": b"\x22" * 64,
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


async def _columns(engine: AsyncEngine, table: str) -> list[dict[str, object]]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda c: sa_inspect(c).get_columns(table))


async def _indexes(engine: AsyncEngine, table: str) -> list[dict[str, object]]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda c: sa_inspect(c).get_indexes(table))


async def _unique_constraints(engine: AsyncEngine, table: str) -> list[dict[str, object]]:
    async with engine.connect() as conn:
        return await conn.run_sync(
            lambda c: sa_inspect(c).get_unique_constraints(table),
        )


async def _foreign_keys(engine: AsyncEngine, table: str) -> list[dict[str, object]]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda c: sa_inspect(c).get_foreign_keys(table))


# --- Tests ---------------------------------------------------------------


async def test_upgrade_creates_key_grants_table(engine: AsyncEngine) -> None:
    """AC #1: table exists after upgrade with the expected column set."""
    await _alembic_upgrade()
    assert "key_grants" in await _table_names(engine)
    columns = await _columns(engine, "key_grants")
    assert {col["name"] for col in columns} == EXPECTED_COLUMNS


async def test_round_trip_clean(engine: AsyncEngine) -> None:
    """AC #4: upgrade → downgrade → upgrade round-trips cleanly."""
    await _alembic_upgrade()
    assert "key_grants" in await _table_names(engine)
    await _alembic_downgrade()
    assert "key_grants" not in await _table_names(engine)
    await _alembic_upgrade()
    assert "key_grants" in await _table_names(engine)


async def test_downgrade_drops_table_and_indexes(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade()
    assert "key_grants" not in await _table_names(engine)


async def test_indexes_present_after_upgrade(engine: AsyncEngine) -> None:
    """AC #5: recipient + snapshot_id indexes exist."""
    await _alembic_upgrade()
    indexes = await _indexes(engine, "key_grants")
    names = {idx["name"] for idx in indexes}
    assert names >= EXPECTED_INDEXES


async def test_recipient_index_is_btree(engine: AsyncEngine) -> None:
    """AC #5: recipient index uses BTREE (Postgres default for ``CREATE INDEX``)."""
    await _alembic_upgrade()
    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE tablename = 'key_grants' AND indexname = :name"),
            {"name": "ix_key_grants_recipient_encryption_public_key"},
        )
        indexdef = result.scalar_one()
    assert "using btree" in indexdef.lower()


async def test_unique_constraints_present_after_upgrade(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    uqs = await _unique_constraints(engine, "key_grants")
    names = {uq["name"] for uq in uqs}
    assert names >= EXPECTED_UNIQUE_CONSTRAINTS


async def test_composite_unique_columns_are_snapshot_then_recipient(
    engine: AsyncEngine,
) -> None:
    """AC #2: composite UNIQUE is the expected column ordering."""
    await _alembic_upgrade()
    uqs = await _unique_constraints(engine, "key_grants")
    composite = next(uq for uq in uqs if uq["name"] == "uq_key_grants_snapshot_recipient")
    assert composite["column_names"] == [
        "snapshot_id",
        "recipient_encryption_public_key",
    ]


async def test_unique_snapshot_recipient_pair_rejected(
    engine: AsyncEngine,
) -> None:
    """AC #2: duplicate (snapshot_id, recipient) is rejected."""
    await _alembic_upgrade()
    recipient = f"recipient_{uuid.uuid4().hex}"
    async with engine.begin() as conn:
        snapshot_id = await _insert_snapshot(conn)
        await conn.execute(
            INSERT_SQL,
            _row(snapshot_id, recipient_encryption_public_key=recipient),
        )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                INSERT_SQL,
                _row(snapshot_id, recipient_encryption_public_key=recipient),
            )


async def test_different_recipients_same_snapshot_accepted(
    engine: AsyncEngine,
) -> None:
    """Edge case: multiple recipients per snapshot are allowed."""
    await _alembic_upgrade()
    async with engine.begin() as conn:
        snapshot_id = await _insert_snapshot(conn)
        await conn.execute(
            INSERT_SQL,
            _row(snapshot_id, recipient_encryption_public_key="recipient_a"),
        )
        await conn.execute(
            INSERT_SQL,
            _row(snapshot_id, recipient_encryption_public_key="recipient_b"),
        )
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT COUNT(*) FROM key_grants WHERE snapshot_id = :sid",
            ),
            {"sid": snapshot_id},
        )
        assert result.scalar_one() == 2


async def test_unique_grant_id_enforced(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    shared_grant_id = uuid.uuid4()
    async with engine.begin() as conn:
        first_snapshot = await _insert_snapshot(conn)
        await conn.execute(
            INSERT_SQL,
            _row(first_snapshot, grant_id=shared_grant_id),
        )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            second_snapshot = await _insert_snapshot(conn)
            await conn.execute(
                INSERT_SQL,
                _row(second_snapshot, grant_id=shared_grant_id),
            )


async def test_server_defaults_populate_created_at_and_version(
    engine: AsyncEngine,
) -> None:
    """AC #1: created_at server default; version server default."""
    await _alembic_upgrade()
    async with engine.begin() as conn:
        snapshot_id = await _insert_snapshot(conn)
        result = await conn.execute(INSERT_SQL, _row(snapshot_id))
        row = result.one()
    assert row.version == "0.1"
    assert row.created_at is not None
    now = datetime.now(tz=UTC)
    assert abs(row.created_at - now) < timedelta(seconds=5)


async def test_wrapped_snapshot_key_round_trips_60_bytes(
    engine: AsyncEngine,
) -> None:
    """Tampering threat: opaque bytes survive write→read unchanged."""
    await _alembic_upgrade()
    wrapped = bytes(range(60))
    async with engine.begin() as conn:
        snapshot_id = await _insert_snapshot(conn)
        result = await conn.execute(
            INSERT_SQL,
            _row(snapshot_id, wrapped_snapshot_key=wrapped),
        )
        inserted_id = result.one().id
    async with engine.connect() as conn:
        check = await conn.execute(
            text(
                "SELECT wrapped_snapshot_key FROM key_grants WHERE id = :id",
            ),
            {"id": inserted_id},
        )
        stored = check.scalar_one()
    assert bytes(stored) == wrapped


async def test_snapshot_id_fk_to_snapshots_with_restrict(
    engine: AsyncEngine,
) -> None:
    """AC #3: FK on snapshot_id references snapshots(snapshot_id) ON DELETE RESTRICT."""
    await _alembic_upgrade()
    fks = await _foreign_keys(engine, "key_grants")
    assert len(fks) == 1
    fk = fks[0]
    assert fk["name"] == "fk_key_grants_snapshot_id"
    assert fk["constrained_columns"] == ["snapshot_id"]
    assert fk["referred_table"] == "snapshots"
    assert fk["referred_columns"] == ["snapshot_id"]
    assert fk["options"].get("ondelete", "").upper() == "RESTRICT"


async def test_orphan_snapshot_id_rejected_by_fk(engine: AsyncEngine) -> None:
    """AC #3: INSERT with a snapshot_id that has no row in snapshots fails."""
    await _alembic_upgrade()
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(INSERT_SQL, _row(uuid.uuid4()))


async def test_snapshot_delete_blocked_while_grant_exists(
    engine: AsyncEngine,
) -> None:
    """ON DELETE RESTRICT: deleting a snapshot referenced by a grant raises."""
    await _alembic_upgrade()
    async with engine.begin() as conn:
        snapshot_id = await _insert_snapshot(conn)
        await conn.execute(INSERT_SQL, _row(snapshot_id))
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM snapshots WHERE snapshot_id = :sid"),
                {"sid": snapshot_id},
            )


async def test_round_trip_idempotent_upgrade(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_upgrade()
    assert "key_grants" in await _table_names(engine)
