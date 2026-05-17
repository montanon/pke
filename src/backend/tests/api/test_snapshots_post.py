"""HTTP integration tests for ``POST /snapshots`` (HLAM-139).

Mirrors the structure of :mod:`tests.api.test_reports_post`:

* AC #1 — happy path: 201 + correct envelope, row + ``SNAPSHOT_COMMITTED``
  ledger anchor persisted.
* AC #2 — owner signature does not verify → 401, no DB writes.
* AC #3 — duplicate ``snapshot_id`` and duplicate
  ``(owner_signing_public_key, session_nonce)`` → 409 ``snapshot_id_conflict``.
* AC #4..N — payload validation: missing field, wrong version, non-UUID id,
  malformed base64url, extra field, wrong-length binary fields.

Concurrency: a single-snapshot variant of HLAM-82 AC #10 verifies that five
concurrent commits to *different* snapshots produce a strictly linear ledger
chain — the advisory lock in :func:`pke_backend.services.ledger.append_entry`
is what guarantees this; the test pins the behaviour at the HTTP boundary so
a regression in the locking primitive surfaces immediately.
"""

from __future__ import annotations

import asyncio
import itertools
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.encoding import b64url_decode, b64url_encode
from pke_backend.models import EventType, LedgerEntry, Snapshot
from tests.api.conftest import build_signed_commitment


@pytest.fixture
def owner_keypair_alt() -> ec.EllipticCurvePrivateKey:
    """A second, independent owner keypair for collision tests."""
    return ec.generate_private_key(ec.SECP256R1())


# --- AC #1 — happy path ---------------------------------------------------


async def test_post_snapshot_happy_path(
    client: httpx.AsyncClient,
    session: AsyncSession,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Verified commitment → 201, snapshot row, single SNAPSHOT_COMMITTED ledger entry."""
    snapshot_id = uuid.uuid4()
    payload = build_signed_commitment(signer=owner_keypair, snapshot_id=snapshot_id)

    response = await client.post("/snapshots", json=payload)

    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body.keys()) == {
        "snapshot_id",
        "ledger_entry_id",
        "ledger_entry_hash",
        "blob_upload_url",
    }
    assert body["snapshot_id"] == str(snapshot_id)
    assert body["blob_upload_url"] == f"/snapshots/{snapshot_id}/blob"
    assert len(b64url_decode(body["ledger_entry_hash"])) == 32

    rows = (await session.execute(select(Snapshot))).scalars().all()
    assert len(rows) == 1
    assert rows[0].snapshot_id == snapshot_id
    assert rows[0].blob_storage_uri == f"file://blobs/{snapshot_id}/blob.bin"

    entries = (await session.execute(select(LedgerEntry))).scalars().all()
    assert len(entries) == 1
    assert entries[0].event_type is EventType.SNAPSHOT_COMMITTED
    assert entries[0].snapshot_id == snapshot_id
    assert b64url_encode(entries[0].entry_hash) == body["ledger_entry_hash"]


# --- AC #2 — invalid signature -------------------------------------------


async def test_post_snapshot_rejects_invalid_signature(
    client: httpx.AsyncClient,
    session: AsyncSession,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_commitment(signer=owner_keypair)
    sig_bytes = bytearray(b64url_decode(payload["owner_signature"]))
    sig_bytes[-1] ^= 0x01
    payload["owner_signature"] = b64url_encode(bytes(sig_bytes))

    response = await client.post("/snapshots", json=payload)

    assert response.status_code == 401
    assert response.json()["error"] == "signature_invalid"
    # no side effects
    assert (await session.execute(select(Snapshot))).scalars().first() is None
    assert (await session.execute(select(LedgerEntry))).scalars().first() is None


# --- AC #3 — duplicate IDs / collisions ----------------------------------


async def test_post_snapshot_rejects_duplicate_snapshot_id(
    client: httpx.AsyncClient,
    session: AsyncSession,
    owner_keypair: ec.EllipticCurvePrivateKey,
    owner_keypair_alt: ec.EllipticCurvePrivateKey,
) -> None:
    """A second POST with the same ``snapshot_id`` (different owner) → 409."""
    snapshot_id = uuid.uuid4()
    first = build_signed_commitment(signer=owner_keypair, snapshot_id=snapshot_id)
    second = build_signed_commitment(
        signer=owner_keypair_alt,
        snapshot_id=snapshot_id,
        session_nonce=b"\x99" * 16,
    )

    r1 = await client.post("/snapshots", json=first)
    r2 = await client.post("/snapshots", json=second)

    assert r1.status_code == 201
    assert r2.status_code == 409
    assert r2.json()["error"] == "snapshot_id_conflict"

    # Exactly one snapshot + one ledger entry survived.
    assert len((await session.execute(select(Snapshot))).scalars().all()) == 1
    assert len((await session.execute(select(LedgerEntry))).scalars().all()) == 1


async def test_post_snapshot_rejects_session_nonce_replay(
    client: httpx.AsyncClient,
    session: AsyncSession,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Same owner cannot reuse a ``session_nonce`` — UNIQUE constraint → 409."""
    nonce = b"\x77" * 16
    first = build_signed_commitment(signer=owner_keypair, session_nonce=nonce)
    second = build_signed_commitment(signer=owner_keypair, session_nonce=nonce)

    r1 = await client.post("/snapshots", json=first)
    r2 = await client.post("/snapshots", json=second)

    assert r1.status_code == 201
    assert r2.status_code == 409
    assert r2.json()["error"] == "snapshot_id_conflict"

    assert len((await session.execute(select(Snapshot))).scalars().all()) == 1
    assert len((await session.execute(select(LedgerEntry))).scalars().all()) == 1


# --- Payload validation --------------------------------------------------


async def test_post_snapshot_rejects_missing_required_field(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_commitment(signer=owner_keypair)
    del payload["ciphertext_hash"]
    response = await client.post("/snapshots", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_snapshot_rejects_extra_top_level_field(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_commitment(signer=owner_keypair)
    payload["extra"] = "x"
    response = await client.post("/snapshots", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_snapshot_rejects_non_uuid_snapshot_id(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Non-UUID ``snapshot_id`` on create → 422 invalid_payload.

    Unlike :mod:`tests.api.test_reports_post` where a non-UUID maps to 404
    (no such row could ever exist), on create the value is being **persisted**
    as the PK — a malformed value is a payload error, not a missing resource.
    """
    payload = build_signed_commitment(signer=owner_keypair)
    payload["snapshot_id"] = "not-a-uuid"
    response = await client.post("/snapshots", json=payload)
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "invalid_payload"
    # Info-disclosure: never echo the raw input back.
    assert "not-a-uuid" not in body["detail"]


async def test_post_snapshot_rejects_malformed_base64_pubkey(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_commitment(signer=owner_keypair)
    payload["owner_signing_public_key"] = "has+plus/chars"  # rejected by b64url_decode
    response = await client.post("/snapshots", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_snapshot_rejects_wrong_length_ciphertext_hash(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """``ciphertext_hash`` must be exactly 32 bytes (SHA-256)."""
    payload = build_signed_commitment(signer=owner_keypair)
    payload["ciphertext_hash"] = b64url_encode(b"\x11" * 16)  # wrong length
    response = await client.post("/snapshots", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_snapshot_rejects_wrong_length_session_nonce(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """``session_nonce`` must be exactly 16 bytes."""
    payload = build_signed_commitment(signer=owner_keypair)
    payload["session_nonce"] = b64url_encode(b"\x44" * 8)  # wrong length
    response = await client.post("/snapshots", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


# --- Concurrency: ledger chain linearity ---------------------------------


async def test_five_concurrent_snapshot_commits_produce_linear_chain(
    client: httpx.AsyncClient,
    session: AsyncSession,
) -> None:
    """Five concurrent POST /snapshots → 5 ledger entries with a linear chain.

    The advisory lock in :func:`pke_backend.services.ledger.append_entry`
    is what serialises the chain appends; this test pins the behaviour at
    the HTTP boundary so a regression in the locking primitive surfaces
    immediately, regardless of which custody event type triggered it.
    """
    keypairs = [ec.generate_private_key(ec.SECP256R1()) for _ in range(5)]
    payloads = [build_signed_commitment(signer=k) for k in keypairs]

    responses = await asyncio.gather(
        *(client.post("/snapshots", json=p) for p in payloads),
        return_exceptions=False,
    )

    statuses = sorted(r.status_code for r in responses)
    assert statuses == [201, 201, 201, 201, 201], [r.text for r in responses]

    rows = (await session.execute(select(Snapshot))).scalars().all()
    assert len(rows) == 5

    entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.id))).scalars().all()
    assert len(entries) == 5
    assert all(e.event_type is EventType.SNAPSHOT_COMMITTED for e in entries)
    for prev, curr in itertools.pairwise(entries):
        assert curr.previous_entry_hash == prev.entry_hash
