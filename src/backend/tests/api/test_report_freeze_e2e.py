"""End-to-end ledger-chain integrity for the HLAM-79 endpoints.

Exercises a sequence of HTTP calls (report → report → freeze → report) and
verifies that the resulting ledger rows form a single valid hash chain under
:func:`pke_backend.crypto.hashing.verify_hash_chain`.

This is the single test that ties together signature verification, ORM
persistence, ledger linkage, and the protocol's canonical-encoding spec. If
any of those layers regresses, the chain breaks here.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.hashing import verify_hash_chain
from pke_backend.models import EventType, LedgerEntry
from tests.api.conftest import build_signed_freeze, build_signed_report


@pytest.fixture
def reporter_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def freezer_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _ledger_wire_form(entry: LedgerEntry) -> dict[str, object]:
    previous = entry.previous_entry_hash if entry.previous_entry_hash is not None else b"\x00" * 32
    iso = entry.entry_timestamp.isoformat()
    if iso.endswith("+00:00"):
        iso = iso[: -len("+00:00")] + "Z"
    return {
        "type": "ledger_entry",
        "version": entry.version,
        "ledger_entry_id": str(entry.ledger_entry_id),
        "event_type": entry.event_type.value,
        "snapshot_id": str(entry.snapshot_id),
        "payload_hash": b64url_encode(entry.payload_hash),
        "previous_entry_hash": b64url_encode(previous),
        "entry_timestamp": iso,
        "entry_hash": b64url_encode(entry.entry_hash),
    }


async def test_report_freeze_sequence_produces_valid_hash_chain(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
    reporter_keypair: ec.EllipticCurvePrivateKey,
    freezer_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    # 1. report
    first_report = build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair)
    r1 = await client.post("/reports", json=first_report)
    assert r1.status_code == 201
    report_id_one = uuid.UUID(r1.json()["report_id"])

    # 2. another report from a different reporter
    second_reporter = ec.generate_private_key(ec.SECP256R1())
    r2 = await client.post(
        "/reports",
        json=build_signed_report(snapshot_id=seed_snapshot_id, signer=second_reporter),
    )
    assert r2.status_code == 201

    # 3. freeze citing the first report
    f1 = await client.post(
        "/freezes",
        json=build_signed_freeze(
            snapshot_id=seed_snapshot_id,
            triggered_by=str(report_id_one),
            signer=freezer_keypair,
        ),
    )
    assert f1.status_code == 201

    # 4. report after the freeze (still accepted; reports are append-only)
    r3 = await client.post(
        "/reports",
        json=build_signed_report(snapshot_id=seed_snapshot_id, signer=reporter_keypair),
    )
    assert r3.status_code == 201

    entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.id))).scalars().all()
    assert [e.event_type for e in entries] == [
        EventType.REPORTED,
        EventType.REPORTED,
        EventType.FROZEN,
        EventType.REPORTED,
    ]

    chain = [_ledger_wire_form(e) for e in entries]
    # Must validate as a single hash chain — raises on any break.
    verify_hash_chain(chain)

    # Confirm the genesis invariant explicitly: first entry's
    # previous_entry_hash is base64url of 32 zero bytes.
    assert chain[0]["previous_entry_hash"] == b64url_encode(b"\x00" * 32)
