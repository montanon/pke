"""HTTP integration tests for ``POST /freezes`` (HLAM-79 + HLAM-82).

Originally HLAM-79's ACs #4–7. HLAM-82 (Report + Freeze test suite) keeps
the same coverage and adds:

* AC #7 (HLAM-82 numbering): primitive ``is_snapshot_frozen()`` returns
  ``True`` after a successful freeze — the directly-testable surface of
  the cross-feature "POST /key-grants is rejected with 409 snapshot_frozen"
  guarantee.
* AC #7 (HLAM-82, HTTP-level): the full POST /key-grants → 409
  snapshot_frozen path is marked ``@pytest.mark.skip(reason="awaits HLAM-74")``
  so the gap is visible until HLAM-74 lands the POST endpoint.

Covers (existing):

* AC #4 happy path including snapshot ``frozen`` state via ``is_snapshot_frozen``
* AC #5 missing report — also covers the non-UUID ``triggered_by`` variant
* AC #6 duplicate freeze (same snapshot, second valid report)
* AC #7 (HLAM-79 numbering) invalid signature
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
from sqlalchemy.ext.asyncio import AsyncSession

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


# --- Snapshot lookup branch on freeze (parity with /reports) -------------


async def test_post_freeze_rejects_unknown_snapshot(
    client: httpx.AsyncClient,
    session: AsyncSession,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Freeze with a snapshot_id no row resolves to → 404 snapshot_not_found."""
    payload = build_signed_freeze(
        snapshot_id=uuid.uuid4(),
        triggered_by=str(uuid.uuid4()),
        signer=freezer_keypair,
    )
    response = await client.post("/freezes", json=payload)
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"
    assert (await session.execute(select(Freeze))).scalars().first() is None


async def test_post_freeze_rejects_non_uuid_snapshot_id(
    client: httpx.AsyncClient,
    session: AsyncSession,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_freeze(
        snapshot_id=uuid.uuid4(),
        triggered_by=str(uuid.uuid4()),
        signer=freezer_keypair,
    )
    payload["snapshot_id"] = "not-a-uuid"
    response = await client.post("/freezes", json=payload)
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


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
    # Pin which submission won: the persisted row's freeze_id must be one of
    # the two payloads, not an arbitrary third UUID.
    winning_freeze_ids = {uuid.UUID(payload_a["freeze_id"]), uuid.UUID(payload_b["freeze_id"])}
    assert freezes[0].freeze_id in winning_freeze_ids
    winning_triggered = {uuid.UUID(payload_a["triggered_by"]), uuid.UUID(payload_b["triggered_by"])}
    assert freezes[0].triggered_by_report_id in winning_triggered

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


# --- HLAM-82 AC #7 — primitive: frozen state observable -------------------


async def test_is_snapshot_frozen_true_after_freeze(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """HLAM-82 AC #7 (primitive path).

    The HTTP-level form — "POST /key-grants after freeze returns 409
    snapshot_frozen" — depends on HLAM-74's POST /key-grants implementation
    landing. Until then, the directly-testable surface is the primitive
    that the future endpoint will call.
    """
    assert await is_snapshot_frozen(session, seed_snapshot_id) is False

    report_id = await _post_report(client, seed_snapshot_id, reporter_keypair)
    freeze_payload = build_signed_freeze(
        snapshot_id=seed_snapshot_id,
        triggered_by=str(report_id),
        signer=freezer_keypair,
    )
    freeze_response = await client.post("/freezes", json=freeze_payload)
    assert freeze_response.status_code == 201

    assert await is_snapshot_frozen(session, seed_snapshot_id) is True


# --- HLAM-82 AC #7 — HTTP-level, blocked on HLAM-74 ----------------------


@pytest.mark.skip(reason="POST /key-grants is HLAM-74; awaits that ticket landing")
async def test_post_key_grants_rejected_for_frozen_snapshot() -> None:
    """HLAM-82 AC #7 (HTTP path).

    Once HLAM-74 lands the POST /key-grants endpoint, this test should:

    * Seed a snapshot + freeze it via POST /reports → POST /freezes.
    * POST /key-grants for the frozen snapshot.
    * Assert 409 ``snapshot_frozen``.

    The freeze-blocks-grants primitive is already covered by
    :func:`test_is_snapshot_frozen_true_after_freeze`; this stub keeps the
    AC visible in test output until the HTTP path can be exercised.
    """
    raise AssertionError("should not run — see skip reason")
