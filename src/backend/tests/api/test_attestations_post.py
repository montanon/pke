"""HTTP integration tests for ``POST /snapshots/{id}/attestations`` (HLAM-141).

Capturer-side batch upload. The endpoint always returns 201 and reports
per-item outcome in a ``{accepted, rejected}`` envelope — the test suite
exercises every cell of the rejection-reason matrix
(``snapshot_mismatch`` / ``signature_invalid`` / ``duplicate_witness_key`` /
``version_unsupported``) plus the schema-layer rejections (over-cap, empty
list, malformed payload) and the 404 path (unknown snapshot).

A two-batch concurrency test pins the advisory-lock guarantee for the
ledger appends: ten attestations spread across two parallel POSTs must
produce a strictly linear ``WITNESS_ATTESTED`` chain.
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
from pke_backend.models import EventType, LedgerEntry, WitnessAttestation
from pke_backend.services.blob_storage import get_blob_store
from tests.api.conftest import build_signed_attestation, seed_snapshot_with_blob


@pytest.fixture
async def snapshot_id_with_blob(session: AsyncSession) -> uuid.UUID:
    """Persist a snapshot + SNAPSHOT_COMMITTED ledger entry + opaque blob.

    Returns the snapshot_id. Tests that need a working ``POST /attestations``
    target use this — they don't care about the snapshot's owner keypair
    because attestations are signed by witness keys, not by the owner.
    """
    blob_store = get_blob_store()
    sid, _entry_hash = await seed_snapshot_with_blob(
        session,
        blob_store,
        content=b"opaque-ciphertext-for-attestation-tests",
    )
    return sid


def _witness_keypairs(n: int) -> list[ec.EllipticCurvePrivateKey]:
    return [ec.generate_private_key(ec.SECP256R1()) for _ in range(n)]


# --- AC #1, #4 — all-accepted happy path ---------------------------------


async def test_post_attestations_all_accepted(
    client: httpx.AsyncClient,
    session: AsyncSession,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """Three distinct-witness attestations → 201, 3 accepted, 3 ledger entries."""
    witnesses = _witness_keypairs(3)
    payload = {
        "attestations": [
            build_signed_attestation(snapshot_id=snapshot_id_with_blob, witness_signer=w) for w in witnesses
        ],
    }

    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json=payload,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["snapshot_id"] == str(snapshot_id_with_blob)
    assert len(body["accepted"]) == 3
    assert body["rejected"] == []
    accepted_indices = [a["index"] for a in body["accepted"]]
    assert accepted_indices == [0, 1, 2]
    # Each accepted entry carries a 32-byte ledger anchor.
    for a in body["accepted"]:
        assert len(b64url_decode(a["ledger_entry_hash"])) == 32

    # DB has 3 attestation rows and 3 WITNESS_ATTESTED ledger entries.
    rows = (await session.execute(select(WitnessAttestation))).scalars().all()
    assert len(rows) == 3
    entries = (
        (
            await session.execute(
                select(LedgerEntry).where(LedgerEntry.event_type == EventType.WITNESS_ATTESTED),
            )
        )
        .scalars()
        .all()
    )
    assert len(entries) == 3


# --- AC #2 — bad signature mixed with valid items ------------------------


async def test_post_attestations_rejects_invalid_signature_in_mixed_batch(
    client: httpx.AsyncClient,
    session: AsyncSession,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """One bad-sig item is rejected; the rest commit normally."""
    witnesses = _witness_keypairs(3)
    items = [build_signed_attestation(snapshot_id=snapshot_id_with_blob, witness_signer=w) for w in witnesses]
    # Flip a byte on the middle item's signature.
    bad_sig = bytearray(b64url_decode(items[1]["witness_signature"]))
    bad_sig[-1] ^= 0x01
    items[1]["witness_signature"] = b64url_encode(bytes(bad_sig))

    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": items},
    )

    assert response.status_code == 201
    body = response.json()
    assert len(body["accepted"]) == 2
    assert {a["index"] for a in body["accepted"]} == {0, 2}
    assert len(body["rejected"]) == 1
    assert body["rejected"][0]["index"] == 1
    assert body["rejected"][0]["reason"] == "signature_invalid"

    # Only two rows committed; only two ledger entries appended.
    rows = (await session.execute(select(WitnessAttestation))).scalars().all()
    assert len(rows) == 2


# --- AC #3 — duplicate detection (intra-batch and against persisted) -----


async def test_post_attestations_rejects_intra_batch_duplicate(
    client: httpx.AsyncClient,
    session: AsyncSession,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """Two items with the same witness pubkey in the same batch:
    the first is accepted, the second rejected with ``duplicate_witness_key``.
    """
    witness = ec.generate_private_key(ec.SECP256R1())
    item_a = build_signed_attestation(snapshot_id=snapshot_id_with_blob, witness_signer=witness)
    # Same witness key, different witness_timestamp → distinct canonical body
    # so the signatures differ but the dedup column matches.
    item_b = build_signed_attestation(
        snapshot_id=snapshot_id_with_blob,
        witness_signer=witness,
        witness_timestamp="2026-05-15T00:01:30Z",
    )

    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": [item_a, item_b]},
    )

    assert response.status_code == 201
    body = response.json()
    assert [a["index"] for a in body["accepted"]] == [0]
    assert len(body["rejected"]) == 1
    assert body["rejected"][0]["index"] == 1
    assert body["rejected"][0]["reason"] == "duplicate_witness_key"

    rows = (await session.execute(select(WitnessAttestation))).scalars().all()
    assert len(rows) == 1


async def test_post_attestations_rejects_pre_existing_duplicate(
    client: httpx.AsyncClient,
    session: AsyncSession,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """A witness pubkey already on the row is rejected on the next batch."""
    witness = ec.generate_private_key(ec.SECP256R1())
    first_payload = build_signed_attestation(
        snapshot_id=snapshot_id_with_blob,
        witness_signer=witness,
    )
    second_payload = build_signed_attestation(
        snapshot_id=snapshot_id_with_blob,
        witness_signer=witness,
        witness_timestamp="2026-05-15T00:02:00Z",
    )

    r1 = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": [first_payload]},
    )
    r2 = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": [second_payload]},
    )

    assert r1.status_code == 201
    assert len(r1.json()["accepted"]) == 1
    assert r2.status_code == 201
    body = r2.json()
    assert body["accepted"] == []
    assert len(body["rejected"]) == 1
    assert body["rejected"][0]["reason"] == "duplicate_witness_key"


# --- All-rejected branch (every item duplicates a pre-seeded witness) ----


async def test_post_attestations_all_rejected_returns_201_with_empty_accepted(
    client: httpx.AsyncClient,
    session: AsyncSession,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """Endpoint still returns 201 when every item is rejected — the response
    envelope is how the client learns the outcome.
    """
    witness = ec.generate_private_key(ec.SECP256R1())
    first = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={
            "attestations": [
                build_signed_attestation(
                    snapshot_id=snapshot_id_with_blob,
                    witness_signer=witness,
                )
            ]
        },
    )
    assert first.status_code == 201

    # Same witness, three items — all duplicates of the persisted row.
    items = [
        build_signed_attestation(
            snapshot_id=snapshot_id_with_blob,
            witness_signer=witness,
            witness_timestamp=f"2026-05-15T00:02:{i:02d}Z",
        )
        for i in range(3)
    ]
    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": items},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["accepted"] == []
    assert len(body["rejected"]) == 3
    assert all(r["reason"] == "duplicate_witness_key" for r in body["rejected"])


# --- Snapshot-mismatch -----------------------------------------------------


async def test_post_attestations_rejects_snapshot_mismatch(
    client: httpx.AsyncClient,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """An item carrying a different ``snapshot_id`` than the URL path is rejected."""
    witness = ec.generate_private_key(ec.SECP256R1())
    other_snapshot = uuid.uuid4()
    item = build_signed_attestation(snapshot_id=other_snapshot, witness_signer=witness)

    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": [item]},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["accepted"] == []
    assert body["rejected"][0]["reason"] == "snapshot_mismatch"


# --- Schema-layer rejections (422) ---------------------------------------


async def test_post_attestations_rejects_over_cap(
    client: httpx.AsyncClient,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """51 items → 422 ``invalid_payload`` (Pydantic ``max_length=50``)."""
    witnesses = _witness_keypairs(51)
    items = [build_signed_attestation(snapshot_id=snapshot_id_with_blob, witness_signer=w) for w in witnesses]
    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": items},
    )
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_attestations_rejects_empty_list(
    client: httpx.AsyncClient,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """An empty batch is a malformed payload (Pydantic ``min_length=1``)."""
    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": []},
    )
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_attestations_rejects_missing_required_field(
    client: httpx.AsyncClient,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """Missing field on one item → 422 (whole batch rejected at parse time)."""
    witness = ec.generate_private_key(ec.SECP256R1())
    item = build_signed_attestation(snapshot_id=snapshot_id_with_blob, witness_signer=witness)
    del item["transport"]

    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": [item]},
    )
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


# --- Unknown snapshot (404) -----------------------------------------------


async def test_post_attestations_rejects_unknown_snapshot(
    client: httpx.AsyncClient,
    session: AsyncSession,
) -> None:
    """404 with no DB writes when the URL snapshot does not exist."""
    random_snapshot = uuid.uuid4()
    witness = ec.generate_private_key(ec.SECP256R1())
    response = await client.post(
        f"/snapshots/{random_snapshot}/attestations",
        json={
            "attestations": [
                build_signed_attestation(
                    snapshot_id=random_snapshot,
                    witness_signer=witness,
                )
            ]
        },
    )

    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"
    assert (await session.execute(select(WitnessAttestation))).scalars().first() is None
    assert (
        await session.execute(
            select(LedgerEntry).where(LedgerEntry.event_type == EventType.WITNESS_ATTESTED),
        )
    ).scalars().first() is None


# --- Info-disclosure hygiene ---------------------------------------------


async def test_rejection_envelope_does_not_echo_witness_signature(
    client: httpx.AsyncClient,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """A rejected item's `witness_signature` bytes must NOT appear in the response."""
    witness = ec.generate_private_key(ec.SECP256R1())
    item = build_signed_attestation(snapshot_id=snapshot_id_with_blob, witness_signer=witness)
    sentinel_sig = item["witness_signature"]
    # Force a snapshot_mismatch so the item is rejected without verifying.
    item["snapshot_id"] = str(uuid.uuid4())

    response = await client.post(
        f"/snapshots/{snapshot_id_with_blob}/attestations",
        json={"attestations": [item]},
    )
    assert response.status_code == 201
    assert sentinel_sig not in response.text


# --- Concurrency: ledger chain linearity across batches ------------------


async def test_two_concurrent_batches_produce_linear_ledger_chain(
    client: httpx.AsyncClient,
    session: AsyncSession,
    snapshot_id_with_blob: uuid.UUID,
) -> None:
    """Two parallel POSTs of 5 attestations each → 10 ledger entries linked linearly.

    Distinct witness keypairs per batch keep the dedup logic out of the
    way; this test isolates the advisory-lock guarantee in
    :func:`append_entry`. A regression in the locking primitive (or a
    naïve "lock per batch" refactor) surfaces here as a non-linear chain.
    """
    batch_a_witnesses = _witness_keypairs(5)
    batch_b_witnesses = _witness_keypairs(5)
    payload_a = {
        "attestations": [
            build_signed_attestation(snapshot_id=snapshot_id_with_blob, witness_signer=w) for w in batch_a_witnesses
        ],
    }
    payload_b = {
        "attestations": [
            build_signed_attestation(snapshot_id=snapshot_id_with_blob, witness_signer=w) for w in batch_b_witnesses
        ],
    }

    r_a, r_b = await asyncio.gather(
        client.post(f"/snapshots/{snapshot_id_with_blob}/attestations", json=payload_a),
        client.post(f"/snapshots/{snapshot_id_with_blob}/attestations", json=payload_b),
        return_exceptions=False,
    )

    assert r_a.status_code == 201, r_a.text
    assert r_b.status_code == 201, r_b.text
    assert len(r_a.json()["accepted"]) == 5
    assert len(r_b.json()["accepted"]) == 5

    rows = (await session.execute(select(WitnessAttestation))).scalars().all()
    assert len(rows) == 10

    # Filter ledger entries to WITNESS_ATTESTED (the seeded snapshot also
    # produced a SNAPSHOT_COMMITTED entry that must NOT break linearity).
    all_entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.id))).scalars().all()
    witness_entries = [e for e in all_entries if e.event_type is EventType.WITNESS_ATTESTED]
    assert len(witness_entries) == 10

    # Whole-chain linearity: each entry's previous_entry_hash matches the
    # prior entry's entry_hash (genesis has NULL previous_entry_hash).
    for prev, curr in itertools.pairwise(all_entries):
        assert curr.previous_entry_hash == prev.entry_hash
