"""Snapshot read helpers — shared lookup primitive for endpoints that
reference an existing :class:`pke_backend.models.snapshot.Snapshot` row.

This module deliberately holds nothing else: HLAM-79 is the first consumer
of a snapshot lookup, so the helper is single-purpose. As more endpoints
land (HLAM-64 /snapshots POST + GET, HLAM-69 attestations, HLAM-74 grants),
additional read helpers can join.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.models import Snapshot

__all__ = ["get_snapshot_or_404"]


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
