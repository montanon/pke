"""Tests for ``services.snapshots.get_snapshot_or_404`` (HLAM-79)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.services.snapshots import get_snapshot_or_404


async def test_returns_existing_snapshot(session: AsyncSession, seed_snapshot: uuid.UUID) -> None:
    snapshot = await get_snapshot_or_404(session, seed_snapshot)
    assert snapshot.snapshot_id == seed_snapshot


async def test_raises_404_for_missing_snapshot(session: AsyncSession) -> None:
    random_id = uuid.uuid4()
    with pytest.raises(HTTPError) as exc_info:
        await get_snapshot_or_404(session, random_id)
    assert exc_info.value.status_code == 404
    assert exc_info.value.error == "snapshot_not_found"
    assert str(random_id) in exc_info.value.detail
