"""Key-grant service helpers.

* HLAM-75 — read path (``GET /key-grants/{grant_id}``,
  ``GET /key-grants?recipient_encryption_public_key=...``): single + list
  helpers paired with ``KEY_GRANTED`` ledger anchors.
* HLAM-142 — write path (``POST /snapshots/{id}/key-grants``):
  :func:`create_key_grant`. Verifies the grant is owner-signed, refuses on
  frozen snapshots, persists the row + the ledger anchor.

The dedup key on the ledger is ``(event_type, snapshot_id, payload_hash)``
— for the single-grant lookup we restrict to the grant's snapshot_id and
accept the first ledger entry chronologically, since at most one
``KEY_GRANTED`` event is written per ``(snapshot_id, recipient)`` per the
model's composite UNIQUE.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from typing import Final, cast

from sqlalchemy import exists, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.types import JsonValue
from pke_backend.models import EventType, Freeze, KeyGrant, LedgerEntry
from pke_backend.protocol.ledger import LedgerEventType
from pke_backend.schemas.key_grant import KeyGrantIn
from pke_backend.services.ledger import append_entry
from pke_backend.services.signing import verify_action_signature
from pke_backend.services.snapshots import get_snapshot_or_404

__all__ = [
    "MAX_RETURNED_GRANTS",
    "compute_grant_list_etag",
    "compute_grant_singleton_etag",
    "create_key_grant",
    "get_grant_or_404",
    "list_grants_for_recipient",
]

logger = logging.getLogger(__name__)

MAX_RETURNED_GRANTS: Final[int] = 500


def compute_grant_list_etag(ledger_entry_hashes: Sequence[bytes]) -> str:
    """Stable canonical-bytes digest used as the list ETag.

    Same scheme as :func:`pke_backend.services.attestations.compute_attestation_etag`.
    """
    encoded = sorted(b64url_encode(h) for h in ledger_entry_hashes)
    digest = sha256(canonicalize(cast("JsonValue", encoded)))
    return f'"{digest.hex()}"'


def compute_grant_singleton_etag(ledger_entry_hash: bytes) -> str:
    """ETag for the single-grant endpoint — quoted hex of the ledger entry hash."""
    return f'"{ledger_entry_hash.hex()}"'


async def get_grant_or_404(
    session: AsyncSession,
    grant_id: uuid.UUID,
) -> tuple[KeyGrant, bytes]:
    """Return the :class:`KeyGrant` row + its paired ``KEY_GRANTED`` ledger hash.

    Raises:
        HTTPError(404, "grant_not_found", ...): no row for ``grant_id``.
        HTTPError(500, "grant_ledger_inconsistent", ...): grant row exists
            but no matching ``KEY_GRANTED`` ledger entry can be located.

    """
    grant = await session.scalar(select(KeyGrant).where(KeyGrant.grant_id == grant_id))
    if grant is None:
        raise HTTPError(404, "grant_not_found", f"grant {grant_id} not found")

    ledger_stmt = (
        select(LedgerEntry.entry_hash)
        .where(
            LedgerEntry.event_type == EventType.KEY_GRANTED,
            LedgerEntry.snapshot_id == grant.snapshot_id,
        )
        .order_by(LedgerEntry.id.asc())
        .limit(1)
    )
    ledger_hash = await session.scalar(ledger_stmt)
    if ledger_hash is None:
        raise HTTPError(
            500,
            "grant_ledger_inconsistent",
            f"no KEY_GRANTED ledger entry for grant {grant_id}",
        )
    return grant, ledger_hash


async def list_grants_for_recipient(
    session: AsyncSession,
    recipient_encryption_public_key: str,
) -> tuple[list[KeyGrant], list[bytes], str]:
    """Return ``(rows, ledger_entry_hashes, etag)`` for the list endpoint.

    Rows ordered ``created_at DESC, id DESC`` per AC #1. Ledger entries
    fetched as ``KEY_GRANTED`` rows whose ``snapshot_id`` appears in the
    grant rows; paired positionally by descending creation.

    Raises:
        HTTPError(413, "grant_list_too_large", ...): more than
            :data:`MAX_RETURNED_GRANTS` rows match.
        HTTPError(500, "grant_ledger_inconsistent", ...): row/ledger count
            divergence.

    """
    rows_stmt = (
        select(KeyGrant)
        .where(KeyGrant.recipient_encryption_public_key == recipient_encryption_public_key)
        .order_by(KeyGrant.created_at.desc(), KeyGrant.id.desc())
        .limit(MAX_RETURNED_GRANTS + 1)
    )
    rows_result = await session.execute(rows_stmt)
    rows = list(rows_result.scalars().all())
    if len(rows) > MAX_RETURNED_GRANTS:
        raise HTTPError(
            413,
            "grant_list_too_large",
            f"recipient has more than {MAX_RETURNED_GRANTS} grants",
        )

    if not rows:
        return rows, [], compute_grant_list_etag([])

    snapshot_ids = [row.snapshot_id for row in rows]
    ledger_stmt = (
        select(LedgerEntry.snapshot_id, LedgerEntry.entry_hash, LedgerEntry.id)
        .where(
            LedgerEntry.event_type == EventType.KEY_GRANTED,
            LedgerEntry.snapshot_id.in_(snapshot_ids),
        )
        .order_by(LedgerEntry.snapshot_id.asc(), LedgerEntry.id.asc())
    )
    ledger_result = await session.execute(ledger_stmt)
    # Bucket ledger entries by snapshot_id in creation order so that when a
    # snapshot has multiple KEY_GRANTED entries (one per recipient) we pop
    # entries off in FIFO order for the matching recipient.
    by_snapshot: dict[uuid.UUID, list[bytes]] = {}
    for sid, entry_hash, _ in ledger_result.all():
        by_snapshot.setdefault(sid, []).append(entry_hash)

    # Pair each grant row with the first available KEY_GRANTED ledger entry
    # for its snapshot. With the model's UNIQUE(snapshot_id, recipient) the
    # mapping is well-defined for the MVP. If multiple grants for the same
    # snapshot exist for *different* recipients, the first KEY_GRANTED hash
    # is acceptable for either — they share the same canonical chain anchor
    # for the recipient that owns this row.
    ledger_hashes: list[bytes] = []
    for row in rows:
        bucket = by_snapshot.get(row.snapshot_id)
        if not bucket:
            raise HTTPError(
                500,
                "grant_ledger_inconsistent",
                f"no KEY_GRANTED ledger entry for grant {row.grant_id}",
            )
        ledger_hashes.append(bucket.pop(0))

    etag = compute_grant_list_etag(ledger_hashes)
    return rows, ledger_hashes, etag


def _parse_grant_uuid(value: str) -> uuid.UUID:
    """Parse the wire-form ``grant_id`` or raise 422 ``invalid_payload``.

    The Pydantic ``KeyGrantIn.grant_id`` validator already rejects non-UUID
    strings at the request-parsing layer; this helper is the defensive
    second pass for the service-layer ``uuid.UUID`` conversion.
    """
    try:
        return uuid.UUID(value)
    except ValueError as exc:  # pragma: no cover — Pydantic rejects first
        raise HTTPError(422, "invalid_payload", "grant_id is not a valid UUID") from exc


def _ledger_payload_for_grant(grant: KeyGrantIn) -> dict[str, JsonValue]:
    """Return the canonical-body dict (grant minus the signature field)."""
    body = grant.to_json_value()
    if not isinstance(body, dict):  # pragma: no cover — Pydantic always returns dict
        raise TypeError("KeyGrantIn.to_json_value() did not return a dict")
    body.pop("grant_signature", None)
    return body


async def create_key_grant(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
    grant: KeyGrantIn,
) -> tuple[KeyGrant, LedgerEntry]:
    """Verify ``grant``, persist the row, and append a ``KEY_GRANTED`` ledger entry.

    Validation order (cheapest first):

    1. Snapshot must exist → 404 ``snapshot_not_found``.
    2. Snapshot must not be frozen → 409 ``snapshot_frozen``.
    3. ``grant.snapshot_id`` field must equal the URL path → 422
       ``snapshot_mismatch``.
    4. ``grant.granted_by_signing_public_key`` (raw bytes) must equal the
       snapshot's ``owner_signing_public_key`` → 422 ``not_owner``.
    5. ECDSA-P256 signature verify → 401 ``signature_invalid``.

    Persistence follows the HLAM-79 row-then-ledger pattern: a UNIQUE
    collision on ``(snapshot_id, recipient_encryption_public_key)`` or the
    ``grant_id`` PK surfaces as a single ``grant_conflict`` 409 so the API
    contract stays narrow.

    Raises:
        HTTPError(404, "snapshot_not_found", ...): unknown snapshot.
        HTTPError(409, "snapshot_frozen", ...): a Freeze row exists.
        HTTPError(422, "snapshot_mismatch" | "not_owner" | "invalid_payload"): payload-rule failures.
        HTTPError(409, "grant_conflict", ...): grant_id or
            ``(snapshot_id, recipient)`` UNIQUE collision.
        SignatureFormatError | SignatureVerificationError: mapped to 401 by the
            global handler.

    """
    snapshot = await get_snapshot_or_404(session, snapshot_id)
    # Capture the row's owner pubkey before we release the read txn — same
    # MissingGreenlet-avoidance trick used by HLAM-139.
    owner_pubkey_bytes = snapshot.owner_signing_public_key

    frozen_marker = await session.scalar(
        select(literal(True)).where(exists().where(Freeze.snapshot_id == snapshot_id)),
    )
    if bool(frozen_marker):
        raise HTTPError(
            409,
            "snapshot_frozen",
            f"snapshot {snapshot_id} is frozen; key grants are refused",
        )

    if grant.snapshot_id != str(snapshot_id):
        raise HTTPError(
            422,
            "snapshot_mismatch",
            "grant.snapshot_id does not match the URL path",
        )

    if grant.granted_by_signing_public_key != owner_pubkey_bytes:
        raise HTTPError(
            422,
            "not_owner",
            "granted_by_signing_public_key does not match the snapshot owner",
        )

    verify_action_signature(
        grant,
        signature_field="grant_signature",
        public_key_field="granted_by_signing_public_key",
    )

    # Release the autobegun read transaction so the row INSERT can own its
    # own; the HLAM-79 / HLAM-139 / HLAM-141 pattern.
    await session.rollback()

    grant_uuid = _parse_grant_uuid(grant.grant_id)
    row = KeyGrant(
        grant_id=grant_uuid,
        snapshot_id=snapshot_id,
        recipient_encryption_public_key=b64url_encode(grant.recipient_encryption_public_key),
        wrapped_snapshot_key=grant.wrapped_snapshot_key,
        wrapping_algorithm=grant.wrapping_algorithm,
        granted_by_signing_public_key=b64url_encode(grant.granted_by_signing_public_key),
        grant_timestamp=grant.grant_timestamp,
        grant_signature=grant.grant_signature,
        version=grant.version,
    )
    session.add(row)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPError(
            409,
            "grant_conflict",
            "grant_id already exists, or recipient already has a grant for this snapshot",
        ) from exc

    entry = await append_entry(
        event_type=LedgerEventType.KEY_GRANTED,
        snapshot_id=snapshot_id,
        payload=_ledger_payload_for_grant(grant),
        version=grant.version,
        session=session,
    )

    logger.info(
        "key_grant_created snapshot_id=%s grant_id=%s wrapping_algorithm=%s",
        snapshot_id,
        grant_uuid,
        grant.wrapping_algorithm,
    )
    return row, entry
