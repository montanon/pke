"""HTTP tests for HLAM-82 ACs #8 and #9 — list-report / list-freeze GET endpoints.

Both endpoints live on the snapshots router (HLAM-65's
``src/backend/src/pke_backend/api/snapshots.py``) and share the
ledger-pairing + ETag scheme that HLAM-70 / HLAM-75 also use.

The tests POST through the actual ``/reports`` and ``/freezes`` endpoints
to seed data — that is what HLAM-82's "happy paths" pre-condition is —
and then GET the list to verify ordering, contents, and the ETag /
``If-None-Match`` short-circuit.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy.ext.asyncio import AsyncSession

from tests.api.conftest import build_signed_freeze, build_signed_report


@pytest.fixture
def reporter_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def freezer_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


async def _post_report(
    client: httpx.AsyncClient,
    snapshot_id: uuid.UUID,
    signer: ec.EllipticCurvePrivateKey,
) -> uuid.UUID:
    payload = build_signed_report(snapshot_id=snapshot_id, signer=signer)
    response = await client.post("/reports", json=payload)
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["report_id"])


# --- AC #8 — GET /snapshots/{id}/reports ----------------------------------


async def test_list_reports_orders_by_created_at_asc(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Three reports → listed in ``created_at ASC`` order (HLAM-82 AC #8)."""
    first = await _post_report(client, seed_snapshot_id, reporter_keypair)
    second = await _post_report(client, seed_snapshot_id, reporter_keypair)
    third = await _post_report(client, seed_snapshot_id, reporter_keypair)

    response = await client.get(f"/snapshots/{seed_snapshot_id}/reports")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["snapshot_id"] == str(seed_snapshot_id)
    assert [uuid.UUID(r["report_id"]) for r in body["reports"]] == [first, second, third]
    # Each entry surfaces the canonical fields recipients use to anchor.
    for entry in body["reports"]:
        assert entry["snapshot_id"] == str(seed_snapshot_id)
        assert len(entry["ledger_entry_hash"]) == 64  # hex of 32-byte digest
        assert entry["created_at"].endswith("Z")


async def test_list_reports_empty_returns_200_with_empty_list(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
) -> None:
    response = await client.get(f"/snapshots/{seed_snapshot_id}/reports")
    assert response.status_code == 200
    assert response.json() == {"snapshot_id": str(seed_snapshot_id), "reports": []}


async def test_list_reports_404_for_unknown_snapshot(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(f"/snapshots/{uuid.uuid4()}/reports")
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


async def test_list_reports_etag_304_on_match(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Repeat fetch with matching ETag short-circuits to 304 (HLAM-82 edge)."""
    await _post_report(client, seed_snapshot_id, reporter_keypair)

    first = await client.get(f"/snapshots/{seed_snapshot_id}/reports")
    assert first.status_code == 200
    etag = first.headers["ETag"]

    second = await client.get(
        f"/snapshots/{seed_snapshot_id}/reports",
        headers={"If-None-Match": etag},
    )
    assert second.status_code == 304
    assert second.content == b""
    assert second.headers["ETag"] == etag


# --- AC #9 — GET /snapshots/{id}/freezes ----------------------------------


async def test_list_freezes_returns_single_with_resolved_triggered_by(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Frozen snapshot → list returns one freeze with ``triggered_by_report_id`` set."""
    report_id = await _post_report(client, seed_snapshot_id, reporter_keypair)
    freeze_response = await client.post(
        "/freezes",
        json=build_signed_freeze(
            snapshot_id=seed_snapshot_id,
            triggered_by=str(report_id),
            signer=freezer_keypair,
        ),
    )
    assert freeze_response.status_code == 201
    freeze_id = uuid.UUID(freeze_response.json()["freeze_id"])

    response = await client.get(f"/snapshots/{seed_snapshot_id}/freezes")

    assert response.status_code == 200
    body = response.json()
    assert body["snapshot_id"] == str(seed_snapshot_id)
    assert len(body["freezes"]) == 1
    only = body["freezes"][0]
    assert uuid.UUID(only["freeze_id"]) == freeze_id
    assert uuid.UUID(only["triggered_by_report_id"]) == report_id
    assert only["freeze_status"] == "active"
    assert len(only["ledger_entry_hash"]) == 64
    assert only["created_at"].endswith("Z")


async def test_list_freezes_empty_returns_200_with_empty_list(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
) -> None:
    response = await client.get(f"/snapshots/{seed_snapshot_id}/freezes")
    assert response.status_code == 200
    assert response.json() == {"snapshot_id": str(seed_snapshot_id), "freezes": []}


async def test_list_freezes_404_for_unknown_snapshot(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(f"/snapshots/{uuid.uuid4()}/freezes")
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


async def test_list_freezes_etag_304_on_match(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    report_id = await _post_report(client, seed_snapshot_id, reporter_keypair)
    freeze_response = await client.post(
        "/freezes",
        json=build_signed_freeze(
            snapshot_id=seed_snapshot_id,
            triggered_by=str(report_id),
            signer=freezer_keypair,
        ),
    )
    assert freeze_response.status_code == 201

    first = await client.get(f"/snapshots/{seed_snapshot_id}/freezes")
    assert first.status_code == 200
    etag = first.headers["ETag"]

    second = await client.get(
        f"/snapshots/{seed_snapshot_id}/freezes",
        headers={"If-None-Match": etag},
    )
    assert second.status_code == 304
    assert second.content == b""
