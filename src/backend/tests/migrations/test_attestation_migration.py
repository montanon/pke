"""Integration tests for migration 0003_create_attestations (HLAM-67).

Requires migration 0002 (``snapshots`` table, HLAM-61) in the chain. When
Postgres is unreachable the ``engine`` fixture skips; when 0002 is missing
``alembic upgrade head`` raises and the suite fails fast — re-enable by
landing HLAM-61.
"""

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
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from pke_backend.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"

UNIQUE_NAME = "uq_witness_attestations_snapshot_witness"
FK_NAME = "fk_witness_attestations_snapshot_id"

INSERT_ATTESTATION_SQL = text(
    "INSERT INTO witness_attestations "
    "(snapshot_id, witness_signing_public_key, witness_timestamp, "
    "transport, proximity_claim, witness_signature) "
    "VALUES (:snapshot_id, :witness_signing_public_key, :witness_timestamp, "
    ":transport, CAST(:proximity_claim AS JSONB), :witness_signature) "
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


def _proximity(**overrides: object) -> str:
    body: dict[str, object] = {
        "method": "nearby_session",
        "exact_location_public": False,
    }
    body.update(overrides)
    return json.dumps(body)


def _attestation_row(snapshot_id: uuid.UUID, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "snapshot_id": snapshot_id,
        "witness_signing_public_key": f"witness_key_{uuid.uuid4().hex}",
        "witness_timestamp": datetime.now(tz=UTC),
        "transport": "multipeerconnectivity",
        "proximity_claim": _proximity(),
        "witness_signature": b"\x11" * 64,
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


async def _seed_snapshot(engine: AsyncEngine) -> uuid.UUID:
    """Insert a minimal `snapshots` row directly.

    The `Snapshot` ORM lives in HLAM-61 and is out of scope for this Story,
    so this seeds via raw SQL touching only the FK target column.
    """
    snapshot_id = uuid.uuid4()
    async with engine.begin() as conn:
        cols = await conn.run_sync(
            lambda c: {col["name"]: col for col in sa_inspect(c).get_columns("snapshots")},
        )
        col_names = list(cols.keys())
        values: dict[str, object] = {"snapshot_id": snapshot_id}
        for name, spec in cols.items():
            if name in {"snapshot_id", "created_at"}:
                continue
            if spec.get("default") is not None or spec.get("server_default") is not None:
                continue
            if spec.get("nullable", True):
                continue
            values[name] = _placeholder_for_column(name, spec)
        placeholders = ", ".join(f":{c}" for c in values)
        col_list = ", ".join(values.keys())
        # SQL is built from introspected column names, not user input.
        await conn.execute(
            text(f"INSERT INTO snapshots ({col_list}) VALUES ({placeholders})"),  # noqa: S608
            values,
        )
        _ = col_names  # keep for debugging
    return snapshot_id


def _placeholder_for_column(name: str, spec: dict[str, object]) -> object:
    """Best-effort placeholder for a NOT-NULL snapshot column without a default."""
    type_repr = str(spec.get("type", "")).upper()
    if "UUID" in type_repr:
        return uuid.uuid4()
    if "BYTEA" in type_repr or "LARGEBINARY" in type_repr:
        return b"\x00" * 32
    if "JSONB" in type_repr or "JSON" in type_repr:
        return json.dumps({})
    if "TIMESTAMP" in type_repr or "DATETIME" in type_repr:
        return datetime.now(tz=UTC)
    if "BOOL" in type_repr:
        return False
    if "INT" in type_repr or "NUMERIC" in type_repr:
        return 0
    return f"seed_{name}"


# --- Tests ---------------------------------------------------------------


async def test_upgrade_creates_witness_attestations_table(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    assert "witness_attestations" in await _table_names(engine)


async def test_downgrade_drops_witness_attestations_table(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade("0002")
    assert "witness_attestations" not in await _table_names(engine)


async def test_round_trip_upgrade_downgrade_upgrade(engine: AsyncEngine) -> None:
    """AC #4: round-trips cleanly."""
    await _alembic_upgrade()
    await _alembic_downgrade()
    await _alembic_upgrade()
    assert "witness_attestations" in await _table_names(engine)


async def test_double_upgrade_is_noop(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_upgrade()
    assert "witness_attestations" in await _table_names(engine)


async def test_unique_constraint_present_after_upgrade(engine: AsyncEngine) -> None:
    """AC #2: composite UNIQUE on (snapshot_id, witness_signing_public_key)."""
    await _alembic_upgrade()
    async with engine.connect() as conn:
        uqs = await conn.run_sync(
            lambda c: sa_inspect(c).get_unique_constraints("witness_attestations"),
        )
    matching = [uq for uq in uqs if uq["name"] == UNIQUE_NAME]
    assert len(matching) == 1
    assert matching[0]["column_names"] == [
        "snapshot_id",
        "witness_signing_public_key",
    ]


async def test_foreign_key_target_is_snapshots_with_restrict(
    engine: AsyncEngine,
) -> None:
    """AC #3: FK to snapshots(snapshot_id) ON DELETE RESTRICT."""
    await _alembic_upgrade()
    async with engine.connect() as conn:
        fks = await conn.run_sync(
            lambda c: sa_inspect(c).get_foreign_keys("witness_attestations"),
        )
    matching = [fk for fk in fks if fk["name"] == FK_NAME]
    assert len(matching) == 1
    fk = matching[0]
    assert fk["referred_table"] == "snapshots"
    assert fk["referred_columns"] == ["snapshot_id"]
    assert fk["options"].get("ondelete", "").upper() == "RESTRICT"


async def test_unique_violation_raises_integrity_error(engine: AsyncEngine) -> None:
    """AC #2: second INSERT with same (snapshot_id, key) is rejected."""
    await _alembic_upgrade()
    snapshot_id = await _seed_snapshot(engine)
    witness_key = f"witness_key_{uuid.uuid4().hex}"
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_ATTESTATION_SQL,
            _attestation_row(snapshot_id, witness_signing_public_key=witness_key),
        )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                INSERT_ATTESTATION_SQL,
                _attestation_row(snapshot_id, witness_signing_public_key=witness_key),
            )


async def test_fk_restrict_blocks_snapshot_delete(engine: AsyncEngine) -> None:
    """AC #3, edge case #3: deleting a referenced snapshot is blocked."""
    await _alembic_upgrade()
    snapshot_id = await _seed_snapshot(engine)
    async with engine.begin() as conn:
        await conn.execute(INSERT_ATTESTATION_SQL, _attestation_row(snapshot_id))
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM snapshots WHERE snapshot_id = :sid"),
                {"sid": snapshot_id},
            )


async def test_different_witness_keys_for_same_snapshot_allowed(
    engine: AsyncEngine,
) -> None:
    """Edge case #4: many witnesses may attest the same snapshot."""
    await _alembic_upgrade()
    snapshot_id = await _seed_snapshot(engine)
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_ATTESTATION_SQL,
            _attestation_row(
                snapshot_id,
                witness_signing_public_key=f"witness_a_{uuid.uuid4().hex}",
            ),
        )
        await conn.execute(
            INSERT_ATTESTATION_SQL,
            _attestation_row(
                snapshot_id,
                witness_signing_public_key=f"witness_b_{uuid.uuid4().hex}",
            ),
        )
    async with engine.connect() as conn:
        count = await conn.execute(
            text(
                "SELECT COUNT(*) FROM witness_attestations WHERE snapshot_id = :sid",
            ),
            {"sid": snapshot_id},
        )
        assert count.scalar_one() == 2


async def test_witness_signature_accepts_any_length(engine: AsyncEngine) -> None:
    """Edge case #1: BYTEA accepts arbitrary length; app enforces 64."""
    await _alembic_upgrade()
    snapshot_id = await _seed_snapshot(engine)
    async with engine.begin() as conn:
        result_short = await conn.execute(
            INSERT_ATTESTATION_SQL,
            _attestation_row(
                snapshot_id,
                witness_signing_public_key=f"witness_short_{uuid.uuid4().hex}",
                witness_signature=b"\x22" * 32,
            ),
        )
        result_long = await conn.execute(
            INSERT_ATTESTATION_SQL,
            _attestation_row(
                snapshot_id,
                witness_signing_public_key=f"witness_long_{uuid.uuid4().hex}",
                witness_signature=b"\x33" * 96,
            ),
        )
        short_id = result_short.one().id
        long_id = result_long.one().id
    async with engine.connect() as conn:
        lengths = await conn.execute(
            text(
                "SELECT id, LENGTH(witness_signature) AS sig_len "
                "FROM witness_attestations WHERE id IN (:a, :b) ORDER BY id",
            ),
            {"a": short_id, "b": long_id},
        )
        rows = {row.id: row.sig_len for row in lengths.all()}
        assert rows[short_id] == 32
        assert rows[long_id] == 96


async def test_server_defaults_populate_created_at_and_version(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    snapshot_id = await _seed_snapshot(engine)
    async with engine.begin() as conn:
        result = await conn.execute(INSERT_ATTESTATION_SQL, _attestation_row(snapshot_id))
        row = result.one()
    assert row.version == "0.1"
    assert row.created_at is not None
    now = datetime.now(tz=UTC)
    assert abs(row.created_at - now) < timedelta(seconds=5)


async def test_proximity_claim_round_trips_arbitrary_jsonb(engine: AsyncEngine) -> None:
    """Edge case #2: JSONB stores any shape losslessly."""
    await _alembic_upgrade()
    snapshot_id = await _seed_snapshot(engine)
    payload = {
        "method": "nearby_session",
        "exact_location_public": False,
        "extra_unknown": [1, 2, 3],
        "nested": {"k": "v", "n": 42},
    }
    async with engine.begin() as conn:
        result = await conn.execute(
            INSERT_ATTESTATION_SQL,
            _attestation_row(snapshot_id, proximity_claim=json.dumps(payload)),
        )
        inserted_id = result.one().id
    async with engine.connect() as conn:
        check = await conn.execute(
            text(
                "SELECT proximity_claim FROM witness_attestations WHERE id = :id",
            ),
            {"id": inserted_id},
        )
        stored = check.scalar_one()
    # asyncpg may decode JSONB to dict directly; tolerate both shapes.
    decoded = stored if isinstance(stored, dict) else json.loads(stored)
    assert decoded == payload


async def test_transport_string_64_rejects_overflow(engine: AsyncEngine) -> None:
    """AC #6: VARCHAR(64) rejects, never silently truncates."""
    await _alembic_upgrade()
    snapshot_id = await _seed_snapshot(engine)
    with pytest.raises((DataError, IntegrityError)):
        async with engine.begin() as conn:
            await conn.execute(
                INSERT_ATTESTATION_SQL,
                _attestation_row(snapshot_id, transport="x" * 65),
            )
