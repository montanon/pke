"""Integration tests for migration 0004_create_reports_freezes (HLAM-77).

These tests run Alembic against a live PostgreSQL instance. They skip
cleanly when PostgreSQL is unreachable (matches the pattern in
``test_initial_migration.py``).

ORM-level model tests in ``tests/models/test_report.py`` and
``tests/models/test_freeze.py`` cover ACs #1–#4, #6, #7 at the
schema-definition layer; this file closes out AC #5 (live round-trip)
plus the FK/UNIQUE/ENUM negative cases.

Snapshot rows inserted by the FK-edge-case tests use the column set
defined by HLAM-61's ``0002_create_snapshots`` migration — every NOT NULL
column is populated with a placeholder value so the FK constraint can
actually fire.
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

EXPECTED_REASON_LABELS = {
    "abuse_concern",
    "legal_request",
    "owner_request",
    "other",
}


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
    """Minimal valid row for HLAM-61's ``snapshots`` table."""
    base: dict[str, object] = {
        "snapshot_id": uuid.uuid4(),
        "ciphertext_hash": b"\x00" * 32,
        "owner_signing_public_key": uuid.uuid4().bytes + uuid.uuid4().bytes,
        "owner_encryption_public_key": b"\x01" * 32,
        "capture_timestamp": datetime.now(tz=UTC),
        "metadata_policy": json.dumps({}),
        "session_nonce": uuid.uuid4().bytes,
        "owner_signature": b"\x02" * 64,
        "blob_storage_uri": "blob://test/snapshot",
    }
    base.update(overrides)
    return base


def _report_row(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "report_id": uuid.uuid4(),
        "snapshot_id": uuid.uuid4(),
        "reason_category": "abuse_concern",
        "reported_by_signing_public_key": b"\x10" * 32,
        "report_signature": b"\x20" * 64,
    }
    base.update(overrides)
    return base


def _freeze_row(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "freeze_id": uuid.uuid4(),
        "snapshot_id": uuid.uuid4(),
        "triggered_by_report_id": uuid.uuid4(),
        "freeze_signature": b"\x30" * 64,
    }
    base.update(overrides)
    return base


INSERT_SNAPSHOT_SQL = text(
    "INSERT INTO snapshots "
    "(snapshot_id, ciphertext_hash, owner_signing_public_key, "
    "owner_encryption_public_key, capture_timestamp, metadata_policy, "
    "session_nonce, owner_signature, blob_storage_uri) "
    "VALUES (:snapshot_id, :ciphertext_hash, :owner_signing_public_key, "
    ":owner_encryption_public_key, :capture_timestamp, "
    "CAST(:metadata_policy AS JSONB), :session_nonce, :owner_signature, "
    ":blob_storage_uri)"
)


INSERT_REPORT_SQL = text(
    "INSERT INTO reports "
    "(report_id, snapshot_id, reason_category, "
    "reported_by_signing_public_key, report_signature) "
    "VALUES (:report_id, :snapshot_id, "
    "CAST(:reason_category AS reason_category), "
    ":reported_by_signing_public_key, :report_signature) "
    "RETURNING id, report_status, created_at"
)

INSERT_FREEZE_SQL = text(
    "INSERT INTO freezes "
    "(freeze_id, snapshot_id, triggered_by_report_id, freeze_signature) "
    "VALUES (:freeze_id, :snapshot_id, :triggered_by_report_id, "
    ":freeze_signature) "
    "RETURNING id, freeze_status, created_at"
)


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


async def _insert_snapshot(engine: AsyncEngine, **overrides: object) -> uuid.UUID:
    row = _snapshot_row(**overrides)
    async with engine.begin() as conn:
        await conn.execute(INSERT_SNAPSHOT_SQL, row)
    return row["snapshot_id"]  # type: ignore[return-value]


# --- AC #1 / AC #2 / AC #5 / AC #6 ---------------------------------------


async def test_upgrade_creates_reports_and_freezes_tables(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    names = await _table_names(engine)
    assert "reports" in names
    assert "freezes" in names


async def test_upgrade_creates_reason_category_enum_with_four_labels(
    engine: AsyncEngine,
) -> None:
    await _alembic_upgrade()
    labels = await _enum_labels(engine, "reason_category")
    assert set(labels) == EXPECTED_REASON_LABELS
    assert len(labels) == 4


async def test_downgrade_drops_tables_and_enum(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade()
    names = await _table_names(engine)
    assert "reports" not in names
    assert "freezes" not in names
    assert await _enum_labels(engine, "reason_category") == []


async def test_round_trip_upgrade_downgrade_upgrade(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade()
    await _alembic_upgrade()
    names = await _table_names(engine)
    assert "reports" in names
    assert "freezes" in names
    assert set(await _enum_labels(engine, "reason_category")) == EXPECTED_REASON_LABELS


async def test_double_upgrade_is_noop(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_upgrade()
    assert "reports" in await _table_names(engine)
    assert "freezes" in await _table_names(engine)


async def test_indexes_present_after_upgrade(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        reports_indexes = await conn.run_sync(
            lambda c: sa_inspect(c).get_indexes("reports"),
        )
        freezes_indexes = await conn.run_sync(
            lambda c: sa_inspect(c).get_indexes("freezes"),
        )
    assert "ix_reports_snapshot_id" in {idx["name"] for idx in reports_indexes}
    assert "ix_freezes_snapshot_id" in {idx["name"] for idx in freezes_indexes}


# --- AC #3 / Edge case 3: UNIQUE on freezes.snapshot_id ------------------


async def test_unique_constraint_blocks_double_freeze(engine: AsyncEngine) -> None:
    """Edge case 3 / STRIDE Tampering: double-freeze is rejected."""
    await _alembic_upgrade()
    snapshot_id = await _insert_snapshot(engine)

    first_report = uuid.uuid4()
    second_report = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_REPORT_SQL,
            _report_row(report_id=first_report, snapshot_id=snapshot_id),
        )
        await conn.execute(
            INSERT_REPORT_SQL,
            _report_row(report_id=second_report, snapshot_id=snapshot_id),
        )
        await conn.execute(
            INSERT_FREEZE_SQL,
            _freeze_row(
                snapshot_id=snapshot_id,
                triggered_by_report_id=first_report,
            ),
        )

    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                INSERT_FREEZE_SQL,
                _freeze_row(
                    snapshot_id=snapshot_id,
                    triggered_by_report_id=second_report,
                ),
            )


# --- AC #4 / Edge case 2: FK fk_freezes_triggered_by_report_id ----------


async def test_freeze_with_unknown_report_id_raises_integrity_error(
    engine: AsyncEngine,
) -> None:
    """Edge case 2 / STRIDE Tampering: orphan freeze is rejected."""
    await _alembic_upgrade()
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                INSERT_FREEZE_SQL,
                _freeze_row(triggered_by_report_id=uuid.uuid4()),
            )


async def test_freeze_fk_targets_report_id_business_key_not_surrogate(
    engine: AsyncEngine,
) -> None:
    """The FK points at ``reports.report_id`` (UUID), not ``reports.id``."""
    await _alembic_upgrade()
    async with engine.connect() as conn:
        fks = await conn.run_sync(
            lambda c: sa_inspect(c).get_foreign_keys("freezes"),
        )
    triggered_fk = next(
        fk for fk in fks if fk["constrained_columns"] == ["triggered_by_report_id"]
    )
    assert triggered_fk["referred_table"] == "reports"
    assert triggered_fk["referred_columns"] == ["report_id"]


# --- Edge case 1: reports.snapshot_id ON DELETE RESTRICT ----------------


async def test_snapshot_deletion_with_reports_is_blocked(
    engine: AsyncEngine,
) -> None:
    """Edge case 1: deleting a snapshot with reports raises ``IntegrityError``."""
    await _alembic_upgrade()
    snapshot_id = await _insert_snapshot(engine)

    async with engine.begin() as conn:
        await conn.execute(
            INSERT_REPORT_SQL,
            _report_row(snapshot_id=snapshot_id),
        )

    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM snapshots WHERE snapshot_id = :snapshot_id"),
                {"snapshot_id": snapshot_id},
            )


async def test_report_deletion_with_freezes_is_blocked(
    engine: AsyncEngine,
) -> None:
    """The freezes→reports FK also enforces ``ON DELETE RESTRICT``."""
    await _alembic_upgrade()
    snapshot_id = await _insert_snapshot(engine)
    report_id = uuid.uuid4()

    async with engine.begin() as conn:
        await conn.execute(
            INSERT_REPORT_SQL,
            _report_row(report_id=report_id, snapshot_id=snapshot_id),
        )
        await conn.execute(
            INSERT_FREEZE_SQL,
            _freeze_row(
                snapshot_id=snapshot_id,
                triggered_by_report_id=report_id,
            ),
        )

    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM reports WHERE report_id = :report_id"),
                {"report_id": report_id},
            )


# --- Server defaults ----------------------------------------------------


async def test_report_status_server_default_is_pending(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    snapshot_id = await _insert_snapshot(engine)
    async with engine.begin() as conn:
        result = await conn.execute(
            INSERT_REPORT_SQL,
            _report_row(snapshot_id=snapshot_id),
        )
        row = result.one()
    assert row.report_status == "pending"


async def test_freeze_status_server_default_is_active(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    snapshot_id = await _insert_snapshot(engine)
    report_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            INSERT_REPORT_SQL,
            _report_row(report_id=report_id, snapshot_id=snapshot_id),
        )
        result = await conn.execute(
            INSERT_FREEZE_SQL,
            _freeze_row(
                snapshot_id=snapshot_id,
                triggered_by_report_id=report_id,
            ),
        )
        row = result.one()
    assert row.freeze_status == "active"


async def test_created_at_server_default_populates_now(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    snapshot_id = await _insert_snapshot(engine)
    async with engine.begin() as conn:
        result = await conn.execute(
            INSERT_REPORT_SQL,
            _report_row(snapshot_id=snapshot_id),
        )
        row = result.one()
    assert row.created_at is not None
    assert abs(row.created_at - datetime.now(tz=UTC)) < timedelta(seconds=5)


# --- Edge case 4: ENUM is case-sensitive --------------------------------


async def test_invalid_reason_category_value_is_rejected(
    engine: AsyncEngine,
) -> None:
    """Edge case 4: ``"Abuse"`` ≠ ``"abuse_concern"`` (ENUM is case-sensitive)."""
    await _alembic_upgrade()
    with pytest.raises((DataError, IntegrityError)):
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO reports "
                    "(report_id, snapshot_id, reason_category, "
                    "reported_by_signing_public_key, report_signature) "
                    "VALUES (:report_id, :snapshot_id, "
                    "CAST(:reason_category AS reason_category), "
                    ":pk, :sig)"
                ),
                {
                    "report_id": uuid.uuid4(),
                    "snapshot_id": uuid.uuid4(),
                    "reason_category": "Abuse",
                    "pk": b"\x10" * 32,
                    "sig": b"\x20" * 64,
                },
            )
