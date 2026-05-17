"""Snapshot read helpers — shared lookup primitives for endpoints that
reference an existing :class:`pke_backend.models.snapshot.Snapshot` row.

HLAM-79 introduced :func:`get_snapshot_or_404`; HLAM-65 extends the module
with :func:`fetch_snapshot_for_response`, which joins the snapshot row, its
``SNAPSHOT_COMMITTED`` ledger anchor, and the cross-feature ``frozen`` flag
(LEFT JOIN onto ``freezes``) so the GET handler can hand a single tuple to
:meth:`pke_backend.schemas.snapshot.SnapshotOut.from_persisted`.
"""

from __future__ import annotations

import uuid

from sqlalchemy import exists, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.models import EventType, Freeze, LedgerEntry, Snapshot

__all__ = ["fetch_snapshot_for_response", "get_snapshot_or_404"]


async def get_snapshot_or_404(session: AsyncSession, snapshot_id: uuid.UUID) -> Snapshot:
    """Return the :class:`Snapshot` row for ``snapshot_id`` or raise 404.

    Raises ``HTTPError(404, "snapshot_not_found", ...)`` if the row does not
    exist. The error envelope is delivered by the global handler in
    :mod:`pke_backend.api.errors`.
    """
    snapshot = await session.scalar(select(Snapshot).where(Snapshot.snapshot_id == snapshot_id))
    if snapshot is None:
        raise HTTPError(404, "snapshot_not_found", f"snapshot {snapshot_id} not found")
    return snapshot


async def fetch_snapshot_for_response(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
) -> tuple[Snapshot, bytes, bool]:
    """Return ``(snapshot, ledger_entry_hash, frozen)`` for the GET endpoint.

    Reads the snapshot row, joins the matching ``SNAPSHOT_COMMITTED`` ledger
    entry (there must be exactly one — the F1 append happens inside the
    snapshot-create transaction), and derives the ``frozen`` flag from an
    ``EXISTS`` against the freezes table.

    Raises:
        HTTPError(404, "snapshot_not_found", ...): no row for ``snapshot_id``.
        HTTPError(500, "ledger_entry_missing", ...): a snapshot row exists
            but its ``SNAPSHOT_COMMITTED`` ledger anchor cannot be located.
            Should be unreachable in production — F1's POST writes the row
            and the ledger entry in the same transaction.

    """
    snapshot = await get_snapshot_or_404(session, snapshot_id)

    ledger_stmt = (
        select(LedgerEntry.entry_hash)
        .where(
            LedgerEntry.event_type == EventType.SNAPSHOT_COMMITTED,
            LedgerEntry.snapshot_id == snapshot_id,
        )
        .order_by(LedgerEntry.id.asc())
        .limit(1)
    )
    ledger_entry_hash = await session.scalar(ledger_stmt)
    if ledger_entry_hash is None:
        raise HTTPError(
            500,
            "ledger_entry_missing",
            f"no SNAPSHOT_COMMITTED ledger entry for snapshot {snapshot_id}",
        )

    frozen_stmt = select(literal(True)).where(exists().where(Freeze.snapshot_id == snapshot_id))
    frozen_marker = await session.scalar(frozen_stmt)
    frozen = bool(frozen_marker)
    return snapshot, ledger_entry_hash, frozen
