"""HTTP integration tests for ``POST /freezes`` (HLAM-79, AC #4–7 + edges).

Covers:

* AC #4 happy path including snapshot `frozen` state via ``is_snapshot_frozen``
* AC #5 missing report — also covers the non-UUID ``triggered_by`` variant
* AC #6 duplicate freeze (same snapshot, second valid report)
* AC #7 invalid signature
* Edge: concurrent freezes serialize (one 201, one 409)
* Edge: report after a freeze stays accepted
"""

from __future__ import annotations

import asyncio
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from pke_backend.crypto.encoding import b64url_decode, b64url_encode
from pke_backend.models import EventType, Freeze, LedgerEntry, Report
from pke_backend.services.freezes import is_snapshot_frozen
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


# --- AC #4 — happy path ---------------------------------------------------


async def test_post_freeze_happy_path(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    report_id = await _post_report(client, seed_snapshot_id, reporter_keypair)
    payload = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(report_id),
        signer=freezer_keypair,
    )

    response = await client.post("/freezes", json=payload)

    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body.keys()) == {"freeze_id", "ledger_entry_id", "ledger_entry_hash"}
    assert body["freeze_id"] == payload["freeze_id"]
    assert len(b64url_decode(body["ledger_entry_hash"])) == 32

    # exactly one freeze row referencing the report
    freezes = (await session.execute(select(Freeze))).scalars().all()
    assert len(freezes) == 1
    assert freezes[0].snapshot_id == seed_snapshot_id
    assert freezes[0].triggered_by_report_id == report_id

    # snapshot is now marked frozen via the primitive
    assert await is_snapshot_frozen(session, seed_snapshot_id) is True

    # ledger now has REPORTED then FROZEN
    entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.id))).scalars().all()
    assert [e.event_type for e in entries] == [EventType.REPORTED, EventType.FROZEN]
    assert entries[1].entry_hash == b64url_decode(body["ledger_entry_hash"])
    assert entries[1].previous_entry_hash == entries[0].entry_hash


# --- AC #5 — triggered_by report missing ----------------------------------


async def test_post_freeze_rejects_unknown_triggered_by(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(uuid.uuid4()),
        signer=freezer_keypair,
    )
    response = await client.post("/freezes", json=payload)

    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "triggered_by_report_not_found"
    assert (await session.execute(select(Freeze))).scalars().first() is None
    assert (await session.execute(select(LedgerEntry))).scalars().first() is None


async def test_post_freeze_rejects_non_uuid_triggered_by(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by="not-a-uuid",
        signer=freezer_keypair,
    )
    response = await client.post("/freezes", json=payload)

    assert response.status_code == 422
    assert response.json()["error"] == "triggered_by_report_not_found"
    assert (await session.execute(select(Freeze))).scalars().first() is None


# --- AC #6 — duplicate freeze --------------------------------------------


async def test_post_freeze_rejects_duplicate(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    # Two distinct reports so we can attempt to freeze twice with different
    # ``triggered_by`` values — the UNIQUE on ``snapshot_id`` must still block.
    report_one = await _post_report(client, seed_snapshot_id, reporter_keypair)
    report_two = await _post_report(client, seed_snapshot_id, reporter_keypair)

    first = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(report_one),
        signer=freezer_keypair,
    )
    second = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(report_two),
        signer=freezer_keypair,
    )

    r1 = await client.post("/freezes", json=first)
    r2 = await client.post("/freezes", json=second)

    assert r1.status_code == 201
    assert r2.status_code == 409
    assert r2.json()["error"] == "snapshot_already_frozen"

    freezes = (await session.execute(select(Freeze))).scalars().all()
    assert len(freezes) == 1

    # ledger: REPORTED, REPORTED, FROZEN — no second FROZEN entry
    entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.id))).scalars().all()
    assert [e.event_type for e in entries] == [EventType.REPORTED, EventType.REPORTED, EventType.FROZEN]


# --- AC #7 — invalid freeze signature -------------------------------------


async def test_post_freeze_rejects_invalid_signature(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    report_id = await _post_report(client, seed_snapshot_id, reporter_keypair)
    payload = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(report_id),
        signer=freezer_keypair,
    )
    sig = bytearray(b64url_decode(payload["freeze_signature"]))
    sig[0] ^= 0xFF
    payload["freeze_signature"] = b64url_encode(bytes(sig))

    response = await client.post("/freezes", json=payload)

    assert response.status_code == 401
    assert response.json()["error"] == "signature_invalid"
    assert (await session.execute(select(Freeze))).scalars().first() is None

    # The report from the precondition is still there; no FROZEN entry was added.
    entries = (await session.execute(select(LedgerEntry))).scalars().all()
    assert len(entries) == 1
    assert entries[0].event_type is EventType.REPORTED


# --- Edge: concurrent freezes serialize -----------------------------------


async def test_concurrent_freezes_serialize(
    client: httpx.AsyncClient,
    session: AsyncSession,
    engine: AsyncEngine,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Two parallel POST /freezes for the same snapshot: one 201, one 409."""
    report_one = await _post_report(client, seed_snapshot_id, reporter_keypair)
    report_two = await _post_report(client, seed_snapshot_id, reporter_keypair)

    payload_a = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(report_one),
        signer=freezer_keypair,
    )
    payload_b = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(report_two),
        signer=freezer_keypair,
    )

    results = await asyncio.gather(
        client.post("/freezes", json=payload_a),
        client.post("/freezes", json=payload_b),
        return_exceptions=False,
    )
    statuses = sorted(r.status_code for r in results)
    assert statuses == [201, 409]

    freezes = (await session.execute(select(Freeze))).scalars().all()
    assert len(freezes) == 1

    entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.id))).scalars().all()
    frozen_entries = [e for e in entries if e.event_type is EventType.FROZEN]
    assert len(frozen_entries) == 1


# --- Edge: report after a freeze still accepted ---------------------------


async def test_report_after_freeze_still_accepted(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Per Edge Cases: reports remain append-only after a freeze."""
    report_one = await _post_report(client, seed_snapshot_id, reporter_keypair)
    freeze_payload = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(report_one),
        signer=freezer_keypair,
    )
    freeze_response = await client.post("/freezes", json=freeze_payload)
    assert freeze_response.status_code == 201

    # New report against the same snapshot, post-freeze.
    new_report = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    response = await client.post("/reports", json=new_report)
    assert response.status_code == 201

    reports = (await session.execute(select(Report))).scalars().all()
    assert len(reports) == 2

    entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.id))).scalars().all()
    assert [e.event_type for e in entries] == [
        EventType.REPORTED,
        EventType.FROZEN,
        EventType.REPORTED,
    ]
