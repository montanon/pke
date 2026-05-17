"""Unit tests for ``services.freezes.is_snapshot_frozen`` (HLAM-79, AC #8 primitive).

AC #8 says "after a successful freeze, subsequent POST /key-grants for that
snapshot, F4 rejects with 409 snapshot_frozen". The full HTTP integration
depends on HLAM-74 (POST /key-grants) and HLAM-80 (frozen-flag propagation)
landing — those stories are still "Tareas por hacer". HLAM-79 ships the
primitive that those stories will consume and exercises it directly here.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.models import Freeze, Report
from pke_backend.protocol.report_action import ReasonCategory
from pke_backend.services.freezes import is_snapshot_frozen


async def test_is_snapshot_frozen_false_for_unknown_snapshot(
    session: AsyncSession,
) -> None:
    assert await is_snapshot_frozen(session, uuid.uuid4()) is False


async def test_is_snapshot_frozen_false_when_no_freeze(session: AsyncSession, seed_snapshot: uuid.UUID) -> None:
    """A snapshot with reports but no freeze is still not frozen."""
    report = Report(
        report_id=uuid.uuid4(),
        snapshot_id=seed_snapshot,
        reason_category=ReasonCategory.ABUSE_CONCERN,
        reported_by_signing_public_key=b"\x04" + b"\x60" * 64,
        report_signature=b"\x70" * 64,
    )
    session.add(report)
    await session.commit()

    assert await is_snapshot_frozen(session, seed_snapshot) is False


async def test_is_snapshot_frozen_true_after_freeze(session: AsyncSession, seed_snapshot: uuid.UUID) -> None:
    report_id = uuid.uuid4()
    session.add(
        Report(
            report_id=report_id,
            snapshot_id=seed_snapshot,
            reason_category=ReasonCategory.LEGAL_REQUEST,
            reported_by_signing_public_key=b"\x04" + b"\x60" * 64,
            report_signature=b"\x70" * 64,
        ),
    )
    # Flush so the FK target (``reports.report_id`` — not the surrogate ``id``
    # PK) is visible to the freeze's FK check at commit time. SQLAlchemy's
    # unit-of-work orders against PKs, not arbitrary UNIQUE columns.
    await session.flush()

    session.add(
        Freeze(
            freeze_id=uuid.uuid4(),
            snapshot_id=seed_snapshot,
            triggered_by_report_id=report_id,
            freeze_signature=b"\x80" * 64,
        ),
    )
    await session.commit()

    assert await is_snapshot_frozen(session, seed_snapshot) is True
