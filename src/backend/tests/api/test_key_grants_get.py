"""HTTP integration tests for HLAM-75 — GET /key-grants/{id} + GET /key-grants?recipient...

Two endpoint surfaces:

* ``/key-grants/{grant_id}`` — single grant by id, paired with its
  ``KEY_GRANTED`` ledger entry.
* ``/key-grants?recipient_encryption_public_key=...`` — all grants for a
  given recipient pubkey, ordered ``created_at DESC``.

Both honour ``If-None-Match`` and return canonical ``KeyGrantOut`` shapes
from the schemas module.
"""

from __future__ import annotations

import uuid

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.encoding import b64url_encode
from tests.api.conftest import seed_key_grant


def _recipient_pubkey(prefix_byte: int) -> str:
    """Build a valid base64url-encoded uncompressed P-256 public key."""
    return b64url_encode(b"\x04" + bytes([prefix_byte]) * 64)


# --- AC #1 — list ordered by created_at DESC -----------------------------


async def test_list_grants_orders_by_created_at_desc(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    recipient = _recipient_pubkey(0x10)
    first, _ = await seed_key_grant(
        session,
        snapshot_id=seed_snapshot_id,
        recipient_encryption_public_key=recipient,
        ledger_entry_hash=b"\x01" * 32,
    )
    # Insert a second snapshot+grant so we have two distinct grants for the
    # same recipient. Both grants share the same recipient pubkey across
    # different snapshots — that's the recipient's grants list.
    from datetime import UTC, datetime

    from pke_backend.models import CIPHERTEXT_HASH_BYTES, SESSION_NONCE_BYTES, SNAPSHOT_VERSION, Snapshot

    snapshot_two_id = uuid.uuid4()
    session.add(
        Snapshot(
            snapshot_id=snapshot_two_id,
            ciphertext_hash=b"\x77" * CIPHERTEXT_HASH_BYTES,
            owner_signing_public_key=b"\x04" + b"\x88" * 64,
            owner_encryption_public_key=b"\x04" + b"\x99" * 64,
            capture_timestamp=datetime.now(tz=UTC),
            metadata_policy={"location_public": False, "media_type": "photo"},
            session_nonce=b"\xaa" * SESSION_NONCE_BYTES,
            owner_signature=b"\xbb" * 64,
            version=SNAPSHOT_VERSION,
            blob_storage_uri="file://blobs/two/blob.bin",
        )
    )
    await session.commit()
    second, _ = await seed_key_grant(
        session,
        snapshot_id=snapshot_two_id,
        recipient_encryption_public_key=recipient,
        ledger_entry_hash=b"\x02" * 32,
    )

    response = await client.get(
        "/key-grants",
        params={"recipient_encryption_public_key": recipient},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["recipient_encryption_public_key"] == recipient
    assert len(body["grants"]) == 2
    # Newest first → second grant precedes first.
    assert uuid.UUID(body["grants"][0]["grant_id"]) == second.grant_id
    assert uuid.UUID(body["grants"][1]["grant_id"]) == first.grant_id


# --- AC #2 — recipient with no grants ------------------------------------


async def test_list_grants_empty_returns_200_with_empty_list(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(
        "/key-grants",
        params={"recipient_encryption_public_key": _recipient_pubkey(0x42)},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["grants"] == []


# --- AC #3 — malformed recipient pubkey ----------------------------------


async def test_list_grants_400_on_malformed_pubkey_alphabet(
    client: httpx.AsyncClient,
) -> None:
    """`+` and `/` are standard-base64 characters — rejected by b64url_decode."""
    response = await client.get(
        "/key-grants",
        params={"recipient_encryption_public_key": "has+plus/chars"},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "invalid_recipient_pubkey"
    # Detail must not echo the raw input.
    assert "has+plus" not in body["detail"]


async def test_list_grants_400_on_wrong_byte_length(
    client: httpx.AsyncClient,
) -> None:
    """A valid base64url string that decodes to the wrong length → 400."""
    short_pubkey = b64url_encode(b"\x04" + b"\x01" * 10)  # 11 bytes, not 65
    response = await client.get(
        "/key-grants",
        params={"recipient_encryption_public_key": short_pubkey},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_recipient_pubkey"


# --- AC #4 — single grant by id ------------------------------------------


async def test_get_grant_by_id_returns_grant(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    recipient = _recipient_pubkey(0x55)
    grant, ledger_hash = await seed_key_grant(
        session,
        snapshot_id=seed_snapshot_id,
        recipient_encryption_public_key=recipient,
        ledger_entry_hash=b"\x66" * 32,
    )

    response = await client.get(f"/key-grants/{grant.grant_id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert uuid.UUID(body["grant_id"]) == grant.grant_id
    assert body["recipient_encryption_public_key"] == recipient
    assert body["ledger_entry_hash"] == ledger_hash.hex()
    assert body["grant_timestamp"].endswith("Z")


# --- AC #5 — missing grant by id -----------------------------------------


async def test_get_grant_by_id_returns_404_for_unknown(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(f"/key-grants/{uuid.uuid4()}")
    assert response.status_code == 404
    assert response.json()["error"] == "grant_not_found"


async def test_get_grant_by_id_returns_404_for_non_uuid_path(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/key-grants/not-a-uuid")
    assert response.status_code == 404
    assert response.json()["error"] == "grant_not_found"


# --- AC #6 — single-grant entry has hex hashes + ISO-8601 ---------------


async def test_get_grant_entry_has_canonical_fields(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    grant, ledger_hash = await seed_key_grant(
        session,
        snapshot_id=seed_snapshot_id,
        recipient_encryption_public_key=_recipient_pubkey(0x77),
        ledger_entry_hash=b"\x88" * 32,
    )
    response = await client.get(f"/key-grants/{grant.grant_id}")
    body = response.json()
    assert body["ledger_entry_hash"] == ledger_hash.hex()
    assert body["wrapping_algorithm"] == "ecdhp256+aesgcm256"
    assert body["created_at"].endswith("Z")


# --- AC #7 — If-None-Match → 304 (both endpoints) ------------------------


async def test_get_grant_etag_304_on_match(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    grant, _ = await seed_key_grant(
        session,
        snapshot_id=seed_snapshot_id,
        recipient_encryption_public_key=_recipient_pubkey(0x12),
        ledger_entry_hash=b"\x34" * 32,
    )
    first = await client.get(f"/key-grants/{grant.grant_id}")
    etag = first.headers["ETag"]
    second = await client.get(
        f"/key-grants/{grant.grant_id}",
        headers={"If-None-Match": etag},
    )
    assert second.status_code == 304
    assert second.content == b""


async def test_list_grants_etag_304_on_match(
    client: httpx.AsyncClient,
    session: AsyncSession,
    seed_snapshot_id: uuid.UUID,
) -> None:
    recipient = _recipient_pubkey(0x56)
    await seed_key_grant(
        session,
        snapshot_id=seed_snapshot_id,
        recipient_encryption_public_key=recipient,
        ledger_entry_hash=b"\x78" * 32,
    )
    first = await client.get(
        "/key-grants",
        params={"recipient_encryption_public_key": recipient},
    )
    etag = first.headers["ETag"]
    second = await client.get(
        "/key-grants",
        params={"recipient_encryption_public_key": recipient},
        headers={"If-None-Match": etag},
    )
    assert second.status_code == 304
    assert second.content == b""
