"""HTTP integration tests for HLAM-65 — GET /snapshots/{id} + GET /snapshots/{id}/blob.

The blob is opaque ciphertext; the test fixture seeds a 4096-byte payload
and persists it alongside the snapshot + a synthetic ``SNAPSHOT_COMMITTED``
ledger entry so the join in
:func:`pke_backend.services.snapshots.fetch_snapshot_for_response`
resolves. ETag tests rely on the contract that the blob endpoint's ETag is
the hex of ``Snapshot.ciphertext_hash`` (which equals the SHA-256 of the
blob bytes per the snapshot-commitment invariant).
"""

from __future__ import annotations

import hashlib
import os
import uuid

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.models import Freeze
from pke_backend.services.blob_storage import get_blob_store
from tests.api.conftest import seed_snapshot_with_blob


@pytest.fixture
def blob_content() -> bytes:
    """Deterministic 4 KiB blob — large enough to exercise chunked streaming."""
    return os.urandom(4096)


# --- AC #1 — metadata happy path -----------------------------------------


async def test_get_snapshot_returns_full_envelope(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    blob_store = get_blob_store()
    snapshot_id, ledger_hash = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    response = await client.get(f"/snapshots/{snapshot_id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["snapshot_id"] == str(snapshot_id)
    assert body["ledger_entry_hash"] == ledger_hash.hex()
    assert body["blob_url"] == f"/snapshots/{snapshot_id}/blob"
    assert body["frozen"] is False
    assert body["ciphertext_hash"] == hashlib.sha256(blob_content).hexdigest()
    assert body["version"] == "0.1"


# --- AC #2 — missing snapshot --------------------------------------------


async def test_get_snapshot_returns_404_for_unknown(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(f"/snapshots/{uuid.uuid4()}")
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


async def test_get_snapshot_returns_404_for_non_uuid_path(
    client: httpx.AsyncClient,
) -> None:
    """Non-UUID path params can never resolve — answer 404."""
    response = await client.get("/snapshots/not-a-uuid")
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


# --- AC #3 — blob streams with correct headers ---------------------------


async def test_get_blob_streams_with_correct_headers(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    response = await client.get(f"/snapshots/{snapshot_id}/blob")

    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-length"] == str(len(blob_content))
    assert response.headers["etag"] == f'"{hashlib.sha256(blob_content).hexdigest()}"'
    assert response.headers["accept-ranges"] == "bytes"
    assert response.content == blob_content


# --- AC #4 — frozen flag propagation -------------------------------------


async def test_get_snapshot_reports_frozen_true_after_freeze(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    # The freeze FK ``freezes.triggered_by_report_id`` references
    # ``reports.report_id`` with ON DELETE RESTRICT — insert the report
    # row first, then the freeze.
    from pke_backend.models import ReasonCategory, Report

    report_id = uuid.uuid4()
    session.add(
        Report(
            report_id=report_id,
            snapshot_id=snapshot_id,
            reason_category=ReasonCategory.OWNER_REQUEST,
            reported_by_signing_public_key=b"\x04" + b"\x11" * 64,
            report_signature=b"\x22" * 64,
        )
    )
    await session.flush()
    session.add(
        Freeze(
            freeze_id=uuid.uuid4(),
            snapshot_id=snapshot_id,
            triggered_by_report_id=report_id,
            freeze_signature=b"\x00" * 64,
        )
    )
    await session.commit()

    response = await client.get(f"/snapshots/{snapshot_id}")
    assert response.status_code == 200
    assert response.json()["frozen"] is True

    # And the blob is still served (opaque ciphertext).
    blob_response = await client.get(f"/snapshots/{snapshot_id}/blob")
    assert blob_response.status_code == 200
    assert blob_response.content == blob_content


# --- AC #5 — blob row exists but file missing → 500 ----------------------


async def test_get_blob_returns_500_when_file_missing(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)
    # Delete the blob file out-of-band to simulate storage inconsistency.
    (blob_store.root / str(snapshot_id) / "blob.bin").unlink()

    response = await client.get(f"/snapshots/{snapshot_id}/blob")
    assert response.status_code == 500
    assert response.json()["error"] == "blob_storage_inconsistent"


# --- AC #6 — If-None-Match matching → 304 --------------------------------


async def test_get_blob_returns_304_for_matching_etag(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    expected_etag = f'"{hashlib.sha256(blob_content).hexdigest()}"'

    response = await client.get(
        f"/snapshots/{snapshot_id}/blob",
        headers={"If-None-Match": expected_etag},
    )
    assert response.status_code == 304
    assert response.content == b""
    assert response.headers["etag"] == expected_etag


# --- Edge: HEAD returns headers without body -----------------------------


async def test_head_blob_returns_headers_without_body(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    response = await client.head(f"/snapshots/{snapshot_id}/blob")

    assert response.status_code == 200
    assert response.content == b""
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-length"] == str(len(blob_content))
    assert response.headers["accept-ranges"] == "bytes"


# --- Edge: Range bytes=N-M ------------------------------------------------


async def test_get_blob_with_bounded_range_returns_206(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    response = await client.get(
        f"/snapshots/{snapshot_id}/blob",
        headers={"Range": "bytes=0-1023"},
    )

    assert response.status_code == 206
    assert response.content == blob_content[:1024]
    assert response.headers["content-length"] == "1024"
    assert response.headers["content-range"] == f"bytes 0-1023/{len(blob_content)}"


async def test_get_blob_with_open_range_streams_to_end(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    """``bytes=N-`` (open-ended) yields N..end inclusive (resumable downloads)."""
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    response = await client.get(
        f"/snapshots/{snapshot_id}/blob",
        headers={"Range": "bytes=2048-"},
    )
    assert response.status_code == 206
    assert response.content == blob_content[2048:]
    assert response.headers["content-range"] == f"bytes 2048-{len(blob_content) - 1}/{len(blob_content)}"


async def test_get_blob_with_invalid_range_returns_416(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    response = await client.get(
        f"/snapshots/{snapshot_id}/blob",
        headers={"Range": "bytes=99999-100000"},
    )
    assert response.status_code == 416
    assert response.headers["content-range"] == f"bytes */{len(blob_content)}"


async def test_get_blob_with_unsupported_range_form_returns_416(
    client: httpx.AsyncClient,
    session: AsyncSession,
    blob_content: bytes,
) -> None:
    """Suffix-byte form ``bytes=-100`` is rejected per the Story plan."""
    blob_store = get_blob_store()
    snapshot_id, _ = await seed_snapshot_with_blob(session, blob_store, content=blob_content)

    response = await client.get(
        f"/snapshots/{snapshot_id}/blob",
        headers={"Range": "bytes=-100"},
    )
    assert response.status_code == 416


# --- Edge: ledger entry missing → 500 ------------------------------------


async def test_get_snapshot_returns_500_when_ledger_entry_missing(
    client: httpx.AsyncClient,
    session: AsyncSession,
) -> None:
    """Defensive guard from :func:`fetch_snapshot_for_response`.

    Insert a snapshot but no SNAPSHOT_COMMITTED ledger entry, then GET the
    metadata endpoint. Should never happen in production (POST writes both
    in the same transaction), but the guard makes the failure observable.
    """
    from datetime import UTC, datetime

    from pke_backend.models import (
        CIPHERTEXT_HASH_BYTES,
        SESSION_NONCE_BYTES,
        SNAPSHOT_VERSION,
        Snapshot,
    )

    snapshot_id = uuid.uuid4()
    session.add(
        Snapshot(
            snapshot_id=snapshot_id,
            ciphertext_hash=b"\x00" * CIPHERTEXT_HASH_BYTES,
            owner_signing_public_key=b"\x04" + b"\x01" * 64,
            owner_encryption_public_key=b"\x04" + b"\x02" * 64,
            capture_timestamp=datetime.now(tz=UTC),
            metadata_policy={"location_public": False, "media_type": "photo"},
            session_nonce=b"\x03" * SESSION_NONCE_BYTES,
            owner_signature=b"\x04" * 64,
            version=SNAPSHOT_VERSION,
            blob_storage_uri="file:///nowhere",
        )
    )
    await session.commit()

    response = await client.get(f"/snapshots/{snapshot_id}")
    assert response.status_code == 500
    assert response.json()["error"] == "ledger_entry_missing"
