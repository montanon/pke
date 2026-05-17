"""Snapshot read + write helpers — primitives for ``/v1/snapshots`` endpoints.

HLAM-79 introduced :func:`get_snapshot_or_404`; HLAM-65 extended the module
with :func:`fetch_snapshot_for_response`, which joins the snapshot row, its
``SNAPSHOT_COMMITTED`` ledger anchor, and the cross-feature ``frozen`` flag
(LEFT JOIN onto ``freezes``) so the GET handler can hand a single tuple to
:meth:`pke_backend.schemas.snapshot.SnapshotOut.from_persisted`.

HLAM-139 adds the two write helpers:

* :func:`create_snapshot_commitment` — verify the owner signature, persist a
  :class:`Snapshot` row, and append the ``SNAPSHOT_COMMITTED`` ledger anchor
  in two separate transactions (row first, ledger second — same ordering
  rationale as :mod:`pke_backend.services.reports`: a 409 on the unique-key
  collision must not leak an orphan ledger entry).
* :func:`store_snapshot_blob` — verify the uploaded body's SHA-256 against
  the committed ``ciphertext_hash`` before writing to the BlobStore. Two
  hashings (here + inside :meth:`FilesystemBlobStore.put`) keep the abstraction
  clean: the adapter never needs a delete-on-mismatch path.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator

from sqlalchemy import exists, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.types import JsonValue
from pke_backend.models import EventType, Freeze, LedgerEntry, Snapshot
from pke_backend.protocol.ledger import LedgerEventType
from pke_backend.schemas.snapshot import SnapshotCommitmentIn
from pke_backend.services.blob_storage import (
    BlobAlreadyExistsError,
    BlobPutResult,
    BlobStore,
)
from pke_backend.services.ledger import append_entry
from pke_backend.services.signing import verify_action_signature

__all__ = [
    "create_snapshot_commitment",
    "fetch_snapshot_for_response",
    "get_snapshot_or_404",
    "store_snapshot_blob",
]

logger = logging.getLogger(__name__)


def _build_blob_storage_uri(snapshot_id: uuid.UUID) -> str:
    """Mirror the URI HLAM-65's seed helpers use: ``file://blobs/{id}/blob.bin``.

    The string is informational — the actual on-disk path is computed by the
    BlobStore adapter from ``Settings.BLOB_ROOT``. Persisting it on the row
    keeps every snapshot self-describing for audit dumps that don't know
    the adapter's filesystem layout.
    """
    return f"file://blobs/{snapshot_id}/blob.bin"


def _parse_snapshot_uuid(value: str) -> uuid.UUID:
    """Parse the wire-form ``snapshot_id`` or raise 422 ``invalid_payload``.

    On create, a non-UUID is a malformed payload (the client supplies the
    value per ``models/snapshot.py`` docstring); 422 is the honest status.
    """
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPError(422, "invalid_payload", "snapshot_id is not a valid UUID") from exc


async def get_snapshot_or_404(session: AsyncSession, snapshot_id: uuid.UUID) -> Snapshot:
    """Return the :class:`Snapshot` row for ``snapshot_id`` or raise 404.

    Raises ``HTTPError(404, "snapshot_not_found", ...)`` if the row does not
    exist. The error envelope is delivered by the global handler in
    :mod:`pke_backend.api.errors`.
    """
    snapshot = await session.scalar(select(Snapshot).where(Snapshot.snapshot_id == snapshot_id))
    if snapshot is None:
        raise HTTPError(404, "snapshot_not_found", f"snapshot {snapshot_id} not found")
    return snapshot


async def fetch_snapshot_for_response(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
) -> tuple[Snapshot, bytes, bool]:
    """Return ``(snapshot, ledger_entry_hash, frozen)`` for the GET endpoint.

    Reads the snapshot row, joins the matching ``SNAPSHOT_COMMITTED`` ledger
    entry (there must be exactly one — the F1 append happens inside the
    snapshot-create transaction), and derives the ``frozen`` flag from an
    ``EXISTS`` against the freezes table.

    Raises:
        HTTPError(404, "snapshot_not_found", ...): no row for ``snapshot_id``.
        HTTPError(500, "ledger_entry_missing", ...): a snapshot row exists
            but its ``SNAPSHOT_COMMITTED`` ledger anchor cannot be located.
            Should be unreachable in production — F1's POST writes the row
            and the ledger entry in the same transaction.

    """
    snapshot = await get_snapshot_or_404(session, snapshot_id)

    ledger_stmt = (
        select(LedgerEntry.entry_hash)
        .where(
            LedgerEntry.event_type == EventType.SNAPSHOT_COMMITTED,
            LedgerEntry.snapshot_id == snapshot_id,
        )
        .order_by(LedgerEntry.id.asc())
        .limit(1)
    )
    ledger_entry_hash = await session.scalar(ledger_stmt)
    if ledger_entry_hash is None:
        raise HTTPError(
            500,
            "ledger_entry_missing",
            f"no SNAPSHOT_COMMITTED ledger entry for snapshot {snapshot_id}",
        )

    frozen_stmt = select(literal(True)).where(exists().where(Freeze.snapshot_id == snapshot_id))
    frozen_marker = await session.scalar(frozen_stmt)
    frozen = bool(frozen_marker)
    return snapshot, ledger_entry_hash, frozen


def _ledger_payload_for_commitment(commitment: SnapshotCommitmentIn) -> dict[str, JsonValue]:
    """Return the canonical-body dict (commitment minus the owner signature).

    Mirrors :func:`pke_backend.services.reports._ledger_payload`: the ledger
    service canonicalizes this dict to derive ``payload_hash`` — exactly the
    bytes the signing device hashed and ECDSA covered, so the chain anchor
    is bound to the verified payload.
    """
    body = commitment.to_json_value()
    if not isinstance(body, dict):  # pragma: no cover — Pydantic always returns dict
        raise TypeError("SnapshotCommitmentIn.to_json_value() did not return a dict")
    body.pop("owner_signature", None)
    return body


async def create_snapshot_commitment(
    session: AsyncSession,
    commitment: SnapshotCommitmentIn,
) -> tuple[Snapshot, LedgerEntry]:
    """Verify ``commitment``, persist the snapshot row, append ``SNAPSHOT_COMMITTED``.

    Two-transaction shape (snapshot row first, ledger entry second) — matches
    :func:`pke_backend.services.reports.create_report`: a UNIQUE collision on
    ``(owner_signing_public_key, session_nonce)`` or on the ``snapshot_id`` PK
    must surface as 409 without leaving an orphan ledger row behind.

    Raises:
        HTTPError(422, "invalid_payload", ...): ``commitment.snapshot_id`` is
            not a valid UUID.
        HTTPError(409, "snapshot_id_conflict", ...): a snapshot row with this
            ``snapshot_id`` already exists, or the
            ``(owner_signing_public_key, session_nonce)`` pair was already
            used. Both collisions are unrecoverable for the client without
            generating fresh values, so a single ``snapshot_id_conflict``
            code keeps the API contract narrow.
        SignatureFormatError | SignatureVerificationError: handled at the
            global exception layer and mapped to 401.

    """
    snapshot_uuid = _parse_snapshot_uuid(commitment.snapshot_id)
    verify_action_signature(
        commitment,
        signature_field="owner_signature",
        public_key_field="owner_signing_public_key",
    )

    snapshot = Snapshot(
        snapshot_id=snapshot_uuid,
        ciphertext_hash=commitment.ciphertext_hash,
        owner_signing_public_key=commitment.owner_signing_public_key,
        owner_encryption_public_key=commitment.owner_encryption_public_key,
        capture_timestamp=commitment.capture_timestamp,
        metadata_policy=commitment.metadata_policy.model_dump(mode="json"),
        session_nonce=commitment.session_nonce,
        owner_signature=commitment.owner_signature,
        version=commitment.version,
        blob_storage_uri=_build_blob_storage_uri(snapshot_uuid),
    )
    session.add(snapshot)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPError(
            409,
            "snapshot_id_conflict",
            "snapshot_id or (owner_signing_public_key, session_nonce) already exists",
        ) from exc

    entry = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=snapshot_uuid,
        payload=_ledger_payload_for_commitment(commitment),
        version=commitment.version,
        session=session,
    )

    logger.info(
        "snapshot_committed snapshot_id=%s version=%s",
        snapshot_uuid,
        commitment.version,
    )
    return snapshot, entry


async def store_snapshot_blob(
    session: AsyncSession,
    blob_store: BlobStore,
    snapshot_id: uuid.UUID,
    body: bytes,
) -> tuple[Snapshot, BlobPutResult]:
    """Verify the uploaded body's SHA-256 and persist it via ``blob_store``.

    The hash check runs **before** :meth:`BlobStore.put` is called: the
    adapter has no delete-on-mismatch path, so pre-hashing keeps the
    abstraction clean. We pay one extra SHA-256 pass over the body (cheap
    compared to network/disk for any blob size that matters in MVP).

    Raises:
        HTTPError(404, "snapshot_not_found", ...): no row for ``snapshot_id``.
        HTTPError(422, "hash_mismatch", ...): uploaded SHA-256 ≠ committed
            ``ciphertext_hash``. No bytes are written.
        HTTPError(409, "blob_already_uploaded", ...): a blob already exists
            for ``snapshot_id``; second-write attempts are rejected so the
            committed hash on the snapshot row remains authoritative.

    """
    snapshot = await get_snapshot_or_404(session, snapshot_id)
    # Hold onto the committed hash and the snapshot_id as local variables so
    # the caller does not need to touch the ORM row again after this function
    # returns. The autobegun read transaction stays open until the request
    # session is closed; we deliberately do not roll it back because that
    # would expire ``snapshot``'s attributes and a subsequent access would
    # trigger a sync lazy-load inside the AsyncSession event loop
    # ("MissingGreenlet").
    committed_hash = snapshot.ciphertext_hash

    uploaded_hash = sha256(body)
    if uploaded_hash != committed_hash:
        raise HTTPError(
            422,
            "hash_mismatch",
            "uploaded body SHA-256 does not match the committed ciphertext_hash",
        )

    async def _stream() -> AsyncIterator[bytes]:
        yield body

    try:
        result = await blob_store.put(snapshot_id, _stream(), overwrite=False)
    except BlobAlreadyExistsError as exc:
        raise HTTPError(
            409,
            "blob_already_uploaded",
            f"a blob already exists for snapshot {snapshot_id}",
        ) from exc

    # Defensive cross-check: the adapter recomputes SHA-256 while streaming,
    # and we already verified the same bytes above. A divergence here means
    # the body was mutated mid-flight (impossible for an in-memory bytes
    # object, but documented so the invariant is explicit on the read path).
    if result.sha256 != committed_hash:  # pragma: no cover — defensive
        raise HTTPError(
            500,
            "blob_hash_inconsistent",
            f"adapter-computed SHA-256 diverged from pre-checked value for snapshot {snapshot_id}",
        )

    logger.info("snapshot_blob_stored snapshot_id=%s bytes=%d", snapshot_id, len(body))
    return snapshot, result
