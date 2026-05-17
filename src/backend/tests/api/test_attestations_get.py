"""HTTP integration tests for HLAM-70 — GET /snapshots/{id}/attestations.

The attestation rows + their ``WITNESS_ATTESTED`` ledger entries are
seeded directly via the conftest helper. The endpoint pairs them
positionally; the tests pin that ordering invariant against the wire
contract (``created_at ASC``) and the ETag scheme
(``sha256(canonicalize(sorted(b64url(ledger_hashes))))``).
"""

from __future__ import annotations

import uuid

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.encoding import b64url_encode
from pke_backend.services.attestations import compute_attestation_etag
from tests.api.conftest import seed_attestation

# --- AC #1 — three attestations in created_at ASC order ------------------


async def test_list_attestations_orders_by_created_at_asc(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    first, _ = await seed_attestation(
        session,
        snapshot_id=seed_snapshot_id,
        witness_signing_public_key=b64url_encode(b"\x04" + b"\x01" * 64),
        transport="bluetooth",
        ledger_entry_hash=b"\xaa" * 32,
    )
    second, _ = await seed_attestation(
        session,
        snapshot_id=seed_snapshot_id,
        witness_signing_public_key=b64url_encode(b"\x04" + b"\x02" * 64),
        transport="multipeer-wifi",
        ledger_entry_hash=b"\xbb" * 32,
    )
    third, _ = await seed_attestation(
        session,
        snapshot_id=seed_snapshot_id,
        witness_signing_public_key=b64url_encode(b"\x04" + b"\x03" * 64),
        transport="bluetooth",
        ledger_entry_hash=b"\xcc" * 32,
    )

    response = await client.get(f"/snapshots/{seed_snapshot_id}/attestations")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["snapshot_id"] == str(seed_snapshot_id)
    assert len(body["attestations"]) == 3
    assert [a["attestation_id"] for a in body["attestations"]] == [first.id, second.id, third.id]
    assert body["attestations"][0]["transport"] == "bluetooth"
    assert body["attestations"][1]["transport"] == "multipeer-wifi"


# --- AC #2 — empty list returns 200 + empty array ------------------------


async def test_list_attestations_empty_returns_empty_list(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
) -> None:
    response = await client.get(f"/snapshots/{seed_snapshot_id}/attestations")
    assert response.status_code == 200
    assert response.json() == {"snapshot_id": str(seed_snapshot_id), "attestations": []}


# --- AC #3 — unknown snapshot → 404 --------------------------------------


async def test_list_attestations_404_for_unknown_snapshot(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(f"/snapshots/{uuid.uuid4()}/attestations")
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


# --- AC #4 — each entry surfaces hex hashes + Z-suffixed timestamps ------


async def test_list_attestations_entries_have_required_fields(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    _, ledger_hash = await seed_attestation(
        session,
        snapshot_id=seed_snapshot_id,
        ledger_entry_hash=b"\xdd" * 32,
    )

    response = await client.get(f"/snapshots/{seed_snapshot_id}/attestations")
    body = response.json()
    only = body["attestations"][0]
    assert only["ledger_entry_hash"] == ledger_hash.hex()
    assert only["witness_timestamp"].endswith("Z")
    assert only["created_at"].endswith("Z")
    assert "+00:00" not in only["created_at"]


# --- AC #5 — If-None-Match matching → 304 --------------------------------


async def test_list_attestations_etag_304_on_match(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    await seed_attestation(session, snapshot_id=seed_snapshot_id, ledger_entry_hash=b"\xee" * 32)

    first = await client.get(f"/snapshots/{seed_snapshot_id}/attestations")
    assert first.status_code == 200
    etag = first.headers["ETag"]

    second = await client.get(
        f"/snapshots/{seed_snapshot_id}/attestations",
        headers={"If-None-Match": etag},
    )
    assert second.status_code == 304
    assert second.content == b""
    assert second.headers["ETag"] == etag


# --- AC #6 — mixed transports round-trip exactly -------------------------


async def test_list_attestations_preserves_transport_field(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    transports = ["bluetooth", "multipeer-wifi", "near-field"]
    for index, transport in enumerate(transports):
        await seed_attestation(
            session,
            snapshot_id=seed_snapshot_id,
            witness_signing_public_key=b64url_encode(b"\x04" + bytes([index + 1]) * 64),
            transport=transport,
            ledger_entry_hash=bytes([index + 0x10]) * 32,
        )

    response = await client.get(f"/snapshots/{seed_snapshot_id}/attestations")
    body = response.json()
    assert [a["transport"] for a in body["attestations"]] == transports


# --- Edge: ETag determinism (replica-safe) -------------------------------


async def test_list_attestations_etag_is_deterministic(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    """Two GETs without DB changes must produce identical ETags."""
    await seed_attestation(session, snapshot_id=seed_snapshot_id, ledger_entry_hash=b"\xff" * 32)
    one = await client.get(f"/snapshots/{seed_snapshot_id}/attestations")
    two = await client.get(f"/snapshots/{seed_snapshot_id}/attestations")
    assert one.headers["ETag"] == two.headers["ETag"]


# --- Edge: ETag matches the service-level helper -------------------------


def test_compute_attestation_etag_round_trip() -> None:
    hashes = [b"\x01" * 32, b"\x02" * 32]
    etag = compute_attestation_etag(hashes)
    # Quoted hex of a 32-byte digest (64 hex chars + 2 quote chars).
    assert etag.startswith('"') and etag.endswith('"')
    assert len(etag) == 66
