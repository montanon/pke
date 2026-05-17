"""HTTP integration tests for ``POST /reports`` (HLAM-79, AC #1–3 + edges).

The fixture ``client`` already wires the ASGI transport against
``pke_backend.main.app``; ``seed_snapshot_id`` provides a snapshot row whose
owner public key is :func:`owner_keypair`'s public form. Tests cover the
acceptance criteria, signature/payload rejection paths, and the two edge
cases called out in the Story (owner-self-report and double-report from same
reporter).
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.encoding import b64url_decode, b64url_encode
from pke_backend.models import EventType, LedgerEntry, Report
from tests.api.conftest import build_signed_report


@pytest.fixture
def reporter_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


# --- AC #1 — happy path ---------------------------------------------------


async def test_post_report_happy_path(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    response = await client.post("/reports", json=payload)

    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body.keys()) == {"report_id", "ledger_entry_id", "ledger_entry_hash"}
    # report_id echoes the wire id
    assert body["report_id"] == payload["report_id"]
    # ledger_entry_hash decodes to exactly 32 bytes
    assert len(b64url_decode(body["ledger_entry_hash"])) == 32

    # exactly one report row, one REPORTED ledger row, both for this snapshot
    reports = (await session.execute(select(Report))).scalars().all()
    assert len(reports) == 1
    assert reports[0].snapshot_id == seed_snapshot_id
    assert reports[0].reason_category.value == "abuse_concern"

    entries = (await session.execute(select(LedgerEntry))).scalars().all()
    assert len(entries) == 1
    assert entries[0].event_type is EventType.REPORTED
    assert entries[0].snapshot_id == seed_snapshot_id
    assert b64url_encode(entries[0].entry_hash) == body["ledger_entry_hash"]


# --- AC #2 — invalid signature -------------------------------------------


async def test_post_report_rejects_invalid_signature(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    # Flip a byte in the (otherwise valid) signature.
    sig_bytes = bytearray(b64url_decode(payload["report_signature"]))
    sig_bytes[-1] ^= 0x01
    payload["report_signature"] = b64url_encode(bytes(sig_bytes))

    response = await client.post("/reports", json=payload)

    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "signature_invalid"
    # no side effects
    assert (await session.execute(select(Report))).scalars().first() is None
    assert (await session.execute(select(LedgerEntry))).scalars().first() is None


# --- AC #3 — snapshot does not exist -------------------------------------


async def test_post_report_rejects_unknown_snapshot(
    client: httpx.AsyncClient,
    session: AsyncSession,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    random_snapshot = uuid.uuid4()
    payload = build_signed_report(snapshot_id=random_snapshot, signer=reporter_keypair)
    response = await client.post("/reports", json=payload)

    assert response.status_code == 404
    body = response.json()
    assert body["error"] == "snapshot_not_found"
    assert str(random_snapshot) in body["detail"]
    assert (await session.execute(select(Report))).scalars().first() is None
    assert (await session.execute(select(LedgerEntry))).scalars().first() is None


# --- Edge: owner reports own snapshot ------------------------------------


async def test_post_report_accepts_owner_self_report(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """The owner of a snapshot may report it (e.g. takedown of their own data)."""
    payload = build_signed_report(
        snapshot_id=seed_snapshot_id,
        signer=owner_keypair,
        reason_category="owner_request",
    )
    response = await client.post("/reports", json=payload)
    assert response.status_code == 201, response.text
    assert response.json()["report_id"] == payload["report_id"]


# --- Edge: two reports from same reporter --------------------------------


async def test_two_reports_from_same_reporter_both_accepted(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Per Edge Cases: reports are not unique per (snapshot, reporter) in MVP."""
    first = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    second = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)

    r1 = await client.post("/reports", json=first)
    r2 = await client.post("/reports", json=second)

    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["report_id"] != r2.json()["report_id"]
    assert r1.json()["ledger_entry_id"] != r2.json()["ledger_entry_id"]

    reports = (await session.execute(select(Report))).scalars().all()
    assert len(reports) == 2

    entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.id))).scalars().all()
    assert len(entries) == 2
    assert entries[1].previous_entry_hash == entries[0].entry_hash


# --- EC: validation errors -----------------------------------------------


async def test_post_report_rejects_missing_required_field(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    del payload["report_id"]
    response = await client.post("/reports", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_report_rejects_unknown_reason_category(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    payload["reason_category"] = "bogus_reason"
    response = await client.post("/reports", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_report_rejects_extra_top_level_field(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    payload["extra"] = "x"
    response = await client.post("/reports", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_report_rejects_non_uuid_snapshot_id(
    client: httpx.AsyncClient,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """A non-UUID snapshot_id cannot exist; map to 404 snapshot_not_found."""
    payload = build_signed_report(snapshot_id=uuid.uuid4(), signer=reporter_keypair)
    payload["snapshot_id"] = "not-a-uuid"
    response = await client.post("/reports", json=payload)
    # Pydantic accepts arbitrary strings; the service parses to UUID and 404s.
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


async def test_post_report_rejects_non_uuid_report_id(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """A non-UUID ``report_id`` is a malformed payload, not a missing snapshot."""
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    payload["report_id"] = "not-a-uuid"
    response = await client.post("/reports", json=payload)
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "invalid_payload"
    # Detail must not echo the raw input value (info-disclosure hygiene).
    assert "not-a-uuid" not in body["detail"]


async def test_post_report_rejects_wrong_version(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """``version`` is pinned to the locked v0.1 value per the spec."""
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    payload["version"] = "0.2"
    response = await client.post("/reports", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_report_rejects_malformed_base64_pubkey(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Padded / wrong-alphabet base64url surfaces as 422, never 500."""
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    payload["reported_by_signing_public_key"] = "has+plus/chars"  # rejected by b64url_decode
    response = await client.post("/reports", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_report_validation_detail_does_not_echo_raw_input(
    client: httpx.AsyncClient,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """STRIDE info-disclosure: a wide-open ``input`` echo would re-export key bytes."""
    payload = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    sentinel_pubkey = payload["reported_by_signing_public_key"]
    payload["reported_by_signing_public_key"] = sentinel_pubkey  # keep
    payload["reason_category"] = 42  # malformed; will fail validation
    response = await client.post("/reports", json=payload)
    assert response.status_code == 422
    body = response.json()
    # The detail must include the failing field's location, but never the
    # raw pubkey bytes from a different field in the same body.
    assert sentinel_pubkey not in body["detail"]


def test_report_service_log_format_excludes_secret_fields() -> None:
    """STRIDE Info-Disclosure: the ``logger.info`` format string in
    ``services.reports`` must never reference ``reported_by_signing_public_key``
    or ``report_signature``.

    Captures the log line through pytest's ``caplog`` proved unreliable
    across the httpx-ASGI request boundary, so we assert the static property
    by reading the source of the service module directly. If the log line
    moves, this test catches the change immediately.
    """
    from pathlib import Path

    src = (Path(__file__).resolve().parents[2] / "src" / "pke_backend" / "services" / "reports.py").read_text()
    # The single ``logger.info`` call body must reference only safe fields.
    assert "logger.info" in src
    log_line_start = src.index("logger.info")
    log_line_end = src.index(")", log_line_start)
    log_block = src[log_line_start:log_line_end]
    assert "reported_by_signing_public_key" not in log_block
    assert "report_signature" not in log_block
    assert "snapshot_id" in log_block
    assert "reason_category" in log_block
