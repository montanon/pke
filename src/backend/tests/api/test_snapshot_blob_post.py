"""HTTP integration tests for ``POST /snapshots/{id}/blob`` (HLAM-139).

Each test goes end-to-end via the public POST surface:

1. POST a signed commitment whose ``ciphertext_hash`` matches the body we
   intend to upload (so we exercise the full create-then-upload flow, not
   a hand-seeded snapshot row).
2. POST the body to ``/snapshots/{id}/blob`` and assert the verified hash,
   the on-disk blob, and a clean ``GET /blob`` round-trip.

The negative tests skip step 2's success path and instead probe the four
rejection paths the service enforces: hash mismatch (422), unknown
snapshot_id (404), non-UUID path param (404), and re-upload (409).
"""

from __future__ import annotations

import hashlib
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pke_backend.crypto.encoding import b64url_encode
from tests.api.conftest import build_signed_commitment


async def _commit_snapshot(
    client: httpx.AsyncClient,
    *,
    signer: ec.EllipticCurvePrivateKey,
    body: bytes,
    snapshot_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Commit a snapshot whose ``ciphertext_hash`` matches SHA-256(body).

    Returns the persisted ``snapshot_id`` for the blob upload step. Asserts
    201 so a regression in :mod:`tests.api.test_snapshots_post` surfaces here
    too rather than silently failing this module's blob assertions.
    """
    sid = snapshot_id if snapshot_id is not None else uuid.uuid4()
    payload = build_signed_commitment(
        signer=signer,
        snapshot_id=sid,
        ciphertext_hash=hashlib.sha256(body).digest(),
    )
    response = await client.post("/snapshots", json=payload)
    assert response.status_code == 201, response.text
    return sid


# --- Happy path ----------------------------------------------------------


async def test_post_blob_happy_path_round_trips_bytes(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """201 + verified hash, and the GET endpoint streams back identical bytes."""
    body = b"opaque-ciphertext-bytes-" + b"\xaa" * 64
    snapshot_id = await _commit_snapshot(client, signer=owner_keypair, body=body)

    response = await client.post(
        f"/snapshots/{snapshot_id}/blob",
        content=body,
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 201, response.text
    envelope = response.json()
    assert envelope.keys() == {"snapshot_id", "ciphertext_sha256", "byte_length"}
    assert envelope["snapshot_id"] == str(snapshot_id)
    assert envelope["byte_length"] == len(body)
    assert envelope["ciphertext_sha256"] == b64url_encode(hashlib.sha256(body).digest())

    # GET round-trip: identical bytes back out.
    get_response = await client.get(f"/snapshots/{snapshot_id}/blob")
    assert get_response.status_code == 200
    assert get_response.content == body


# --- AC: hash mismatch ---------------------------------------------------


async def test_post_blob_rejects_hash_mismatch(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """Uploaded SHA-256 must match the committed ``ciphertext_hash``."""
    committed_body = b"committed-ciphertext"
    snapshot_id = await _commit_snapshot(client, signer=owner_keypair, body=committed_body)

    wrong_body = b"different-ciphertext"
    response = await client.post(
        f"/snapshots/{snapshot_id}/blob",
        content=wrong_body,
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "hash_mismatch"

    # The blob must NOT have been written (the rejection is pre-write).
    get_response = await client.get(f"/snapshots/{snapshot_id}/blob")
    assert get_response.status_code == 500
    assert get_response.json()["error"] == "blob_storage_inconsistent"


# --- AC: unknown snapshot_id --------------------------------------------


async def test_post_blob_rejects_unknown_snapshot(
    client: httpx.AsyncClient,
) -> None:
    """404 with no snapshot row matching the path param."""
    random_id = uuid.uuid4()
    response = await client.post(
        f"/snapshots/{random_id}/blob",
        content=b"anything",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


async def test_post_blob_rejects_non_uuid_path_param(
    client: httpx.AsyncClient,
) -> None:
    """Non-UUID path param resolves to 404 — mirrors the GET handler's parser."""
    response = await client.post(
        "/snapshots/not-a-uuid/blob",
        content=b"anything",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 404
    assert response.json()["error"] == "snapshot_not_found"


# --- AC: double upload --------------------------------------------------


async def test_post_blob_rejects_second_upload(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """A second POST for the same snapshot → 409 ``blob_already_uploaded``."""
    body = b"once-and-only-once"
    snapshot_id = await _commit_snapshot(client, signer=owner_keypair, body=body)

    first = await client.post(
        f"/snapshots/{snapshot_id}/blob",
        content=body,
        headers={"Content-Type": "application/octet-stream"},
    )
    second = await client.post(
        f"/snapshots/{snapshot_id}/blob",
        content=body,
        headers={"Content-Type": "application/octet-stream"},
    )

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["error"] == "blob_already_uploaded"


# --- Edge: empty body ----------------------------------------------------


async def test_post_blob_accepts_empty_body_when_hash_matches(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
) -> None:
    """A zero-byte ciphertext is uncommon but its hash is well-defined."""
    body = b""
    snapshot_id = await _commit_snapshot(client, signer=owner_keypair, body=body)

    response = await client.post(
        f"/snapshots/{snapshot_id}/blob",
        content=body,
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 201, response.text
    assert response.json()["byte_length"] == 0
    assert response.json()["ciphertext_sha256"] == b64url_encode(hashlib.sha256(b"").digest())


# --- STRIDE info-disclosure: error detail discipline --------------------


@pytest.mark.parametrize(
    ("error_code", "url_template"),
    [
        ("snapshot_not_found", "/snapshots/{sid}/blob"),
        ("hash_mismatch", None),
    ],
)
async def test_post_blob_error_details_do_not_echo_body_bytes(
    client: httpx.AsyncClient,
    owner_keypair: ec.EllipticCurvePrivateKey,
    error_code: str,
    url_template: str | None,
) -> None:
    """Rejection paths must never echo the uploaded bytes back to the client."""
    sentinel = b"SECRET-NEVER-ECHO-" + b"\xff" * 32

    if error_code == "snapshot_not_found":
        url = url_template.format(sid=uuid.uuid4()) if url_template else ""
    else:  # hash_mismatch
        committed_body = b"the-committed-bytes"
        snapshot_id = await _commit_snapshot(client, signer=owner_keypair, body=committed_body)
        url = f"/snapshots/{snapshot_id}/blob"

    response = await client.post(
        url,
        content=sentinel,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.json()["error"] == error_code
    # Body never appears in the error envelope; neither as a hex/base64 fragment.
    assert "SECRET-NEVER-ECHO" not in response.text
    assert b64url_encode(sentinel) not in response.text
