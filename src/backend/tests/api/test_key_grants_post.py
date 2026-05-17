"""HTTP integration tests for ``POST /snapshots/{id}/key-grants`` (HLAM-142).

Owner-side single-item write. Each test exercises one cell of the
validation matrix (owner success / not-owner refusal / frozen refusal /
bad signature / duplicate recipient / snapshot mismatch / unknown snapshot
/ missing bearer / payload validation). The KEY_GRANTED ledger anchor is
verified end-to-end via the existing HLAM-75 ``GET /key-grants/{grant_id}``
read path.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.encoding import b64url_decode, b64url_encode
from pke_backend.models import EventType, Freeze, KeyGrant, LedgerEntry, ReasonCategory, Report
from pke_backend.services.blob_storage import get_blob_store
from tests.api.conftest import build_signed_key_grant, seed_snapshot_with_blob


@pytest.fixture
async def owner_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
async def owned_snapshot(
    session: AsyncSession,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> uuid.UUID:
    """Persist a snapshot owned by ``owner_keypair`` + a blob.

    Reuses :func:`seed_snapshot_with_blob`, which embeds the supplied
    ``owner_keypair``'s public bytes on the snapshot row so the owner-check
    in :func:`create_key_grant` resolves to ``True``.
    """
    blob_store = get_blob_store()
    sid, _ = await seed_snapshot_with_blob(
        session,
        blob_store,
        content=b"opaque-ciphertext-for-key-grant-tests",
        owner_keypair=owner_keypair,
    )
    return sid


# --- AC #1, #2 — happy path: owner success + KEY_GRANTED entry -----------


async def test_post_key_grant_happy_path(
    client: httpx.AsyncClient,
    session: AsyncSession,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Owner-signed grant → 201 + grant row + KEY_GRANTED ledger entry."""
    payload = build_signed_key_grant(snapshot_id=owned_snapshot, owner_signer=owner_keypair)

    response = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)

    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body.keys()) == {"grant_id", "ledger_entry_id", "ledger_entry_hash"}
    assert body["grant_id"] == payload["grant_id"]
    assert len(b64url_decode(body["ledger_entry_hash"])) == 32

    # DB has the grant row + a KEY_GRANTED ledger entry tied to the snapshot.
    rows = (await session.execute(select(KeyGrant))).scalars().all()
    assert len(rows) == 1
    assert rows[0].snapshot_id == owned_snapshot
    assert rows[0].wrapping_algorithm == "ecdhp256+aesgcm256"

    entries = (
        (
            await session.execute(
                select(LedgerEntry).where(LedgerEntry.event_type == EventType.KEY_GRANTED),
            )
        )
        .scalars()
        .all()
    )
    assert len(entries) == 1
    assert b64url_encode(entries[0].entry_hash) == body["ledger_entry_hash"]


async def test_post_key_grant_round_trips_through_get(
    client: httpx.AsyncClient,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Grant just created via POST is retrievable via HLAM-75 GET /key-grants/{grant_id}."""
    payload = build_signed_key_grant(snapshot_id=owned_snapshot, owner_signer=owner_keypair)
    create = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)
    grant_id = create.json()["grant_id"]

    fetched = await client.get(f"/key-grants/{grant_id}")
    assert fetched.status_code == 200
    fetched_body = fetched.json()
    assert fetched_body["grant_id"] == grant_id
    assert fetched_body["snapshot_id"] == str(owned_snapshot)
    assert fetched_body["wrapping_algorithm"] == "ecdhp256+aesgcm256"


# --- AC #1 — non-owner refusal -------------------------------------------


async def test_post_key_grant_rejects_non_owner_signer(
    client: httpx.AsyncClient,
    session: AsyncSession,
    owned_snapshot: uuid.UUID,
) -> None:
    """Signer != snapshot owner → 422 ``not_owner``, no DB writes."""
    impostor = ec.generate_private_key(ec.SECP256R1())
    payload = build_signed_key_grant(snapshot_id=owned_snapshot, owner_signer=impostor)

    response = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)

    assert response.status_code == 422
    assert response.json()["error"] == "not_owner"
    assert (await session.execute(select(KeyGrant))).scalars().first() is None
    assert (
        await session.execute(
            select(LedgerEntry).where(LedgerEntry.event_type == EventType.KEY_GRANTED),
        )
    ).scalars().first() is None


# --- Frozen-snapshot refusal ----------------------------------------------


async def test_post_key_grant_rejects_frozen_snapshot(
    client: httpx.AsyncClient,
    session: AsyncSession,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """A snapshot with a Freeze row rejects new grants with 409 ``snapshot_frozen``."""
    # Freezes carry a FK to reports.report_id with ON DELETE RESTRICT — same
    # row-ordering trick used by test_snapshots_get.py.
    report_id = uuid.uuid4()
    session.add(
        Report(
            report_id=report_id,
            snapshot_id=owned_snapshot,
            reason_category=ReasonCategory.OWNER_REQUEST,
            reported_by_signing_public_key=b"\x04" + b"\x11" * 64,
            report_signature=b"\x22" * 64,
        ),
    )
    await session.flush()
    session.add(
        Freeze(
            freeze_id=uuid.uuid4(),
            snapshot_id=owned_snapshot,
            triggered_by_report_id=report_id,
            freeze_signature=b"\x00" * 64,
        ),
    )
    await session.commit()

    payload = build_signed_key_grant(snapshot_id=owned_snapshot, owner_signer=owner_keypair)
    response = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)

    assert response.status_code == 409
    assert response.json()["error"] == "snapshot_frozen"
    assert (await session.execute(select(KeyGrant))).scalars().first() is None


# --- Bad signature --------------------------------------------------------


async def test_post_key_grant_rejects_invalid_signature(
    client: httpx.AsyncClient,
    session: AsyncSession,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_key_grant(snapshot_id=owned_snapshot, owner_signer=owner_keypair)
    bad_sig = bytearray(b64url_decode(payload["grant_signature"]))
    bad_sig[-1] ^= 0x01
    payload["grant_signature"] = b64url_encode(bytes(bad_sig))

    response = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)

    assert response.status_code == 401
    assert response.json()["error"] == "signature_invalid"
    assert (await session.execute(select(KeyGrant))).scalars().first() is None


# --- Snapshot-mismatch ----------------------------------------------------


async def test_post_key_grant_rejects_snapshot_mismatch(
    client: httpx.AsyncClient,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """grant.snapshot_id different from URL path → 422 ``snapshot_mismatch``."""
    other = uuid.uuid4()
    payload = build_signed_key_grant(snapshot_id=other, owner_signer=owner_keypair)

    response = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)

    assert response.status_code == 422
    assert response.json()["error"] == "snapshot_mismatch"


# --- Duplicate recipient --------------------------------------------------


async def test_post_key_grant_rejects_duplicate_recipient(
    client: httpx.AsyncClient,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Second POST with same recipient pubkey → 409 ``grant_conflict``."""
    same_recipient = b"\x04" + b"\x55" * 64
    first = build_signed_key_grant(
        snapshot_id=owned_snapshot,
        owner_signer=owner_keypair,
        recipient_encryption_public_key=same_recipient,
    )
    second = build_signed_key_grant(
        snapshot_id=owned_snapshot,
        owner_signer=owner_keypair,
        recipient_encryption_public_key=same_recipient,
        grant_timestamp="2026-05-15T00:04:00Z",
    )

    r1 = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=first)
    r2 = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=second)

    assert r1.status_code == 201
    assert r2.status_code == 409
    assert r2.json()["error"] == "grant_conflict"


async def test_post_key_grant_rejects_duplicate_grant_id(
    client: httpx.AsyncClient,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Same grant_id, different recipient → 409 ``grant_conflict`` (PK collision)."""
    same_gid = uuid.uuid4()
    first = build_signed_key_grant(
        snapshot_id=owned_snapshot,
        owner_signer=owner_keypair,
        grant_id=same_gid,
        recipient_encryption_public_key=b"\x04" + b"\xaa" * 64,
    )
    second = build_signed_key_grant(
        snapshot_id=owned_snapshot,
        owner_signer=owner_keypair,
        grant_id=same_gid,
        recipient_encryption_public_key=b"\x04" + b"\xbb" * 64,
    )

    r1 = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=first)
    r2 = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=second)

    assert r1.status_code == 201
    assert r2.status_code == 409
    assert r2.json()["error"] == "grant_conflict"


# --- Unknown snapshot ----------------------------------------------------


async def test_post_key_grant_rejects_unknown_snapshot(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    random_snapshot = uuid.uuid4()
    payload = build_signed_key_grant(snapshot_id=random_snapshot, owner_signer=owner_keypair)
    response = await client.post(f"/snapshots/{random_snapshot}/key-grants", json=payload)
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


# --- Bearer auth gating --------------------------------------------------


async def test_post_key_grant_requires_bearer(
    unauth_client: httpx.AsyncClient,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """No Authorization header → 401 ``unauthenticated``."""
    payload = build_signed_key_grant(snapshot_id=owned_snapshot, owner_signer=owner_keypair)
    response = await unauth_client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)
    assert response.status_code == 401
    # HLAM-122's auth handler uses a nested {error: {code, message}} envelope
    # (distinct from the flat {error, detail} envelope of pke_backend.api.errors).
    body = response.json()
    assert body["error"]["code"] == "unauthenticated"


# --- Payload validation --------------------------------------------------


async def test_post_key_grant_rejects_wrong_wrapping_algorithm(
    client: httpx.AsyncClient,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """An algorithm not in the v0.1 allowlist → 422 ``invalid_payload``."""
    payload = build_signed_key_grant(snapshot_id=owned_snapshot, owner_signer=owner_keypair)
    payload["wrapping_algorithm"] = "xchacha20poly1305"
    response = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_key_grant_rejects_missing_field(
    client: httpx.AsyncClient,
    owned_snapshot: uuid.UUID,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    payload = build_signed_key_grant(snapshot_id=owned_snapshot, owner_signer=owner_keypair)
    del payload["wrapped_snapshot_key"]
    response = await client.post(f"/snapshots/{owned_snapshot}/key-grants", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_payload"


async def test_post_key_grant_rejects_non_uuid_path(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Non-UUID path param resolves to 404 — mirrors the GET handler's parser."""
    payload = build_signed_key_grant(snapshot_id=uuid.uuid4(), owner_signer=owner_keypair)
    response = await client.post("/snapshots/not-a-uuid/key-grants", json=payload)
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"
