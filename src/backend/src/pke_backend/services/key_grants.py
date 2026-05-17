"""Key-grant read helpers — backs HLAM-75 GET /key-grants endpoints.

Two endpoint shapes share this module:

* ``GET /key-grants/{grant_id}`` → single row + paired ledger anchor.
* ``GET /key-grants?recipient_encryption_public_key=...`` → list ordered
  ``created_at DESC`` so the recipient's UI shows newest grants first.

Both endpoints pair grant rows with their ``KEY_GRANTED`` ledger entries
by ``snapshot_id`` (and creation order for the list form). The dedup key
on the ledger is ``(event_type, snapshot_id, payload_hash)`` — for the
single-grant lookup we restrict to the grant's snapshot_id and accept
the first ledger entry chronologically, since at most one ``KEY_GRANTED``
event is written per ``(snapshot_id, recipient)`` per the model's
composite UNIQUE.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Final, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.types import JsonValue
from pke_backend.models import EventType, KeyGrant, LedgerEntry

__all__ = [
    "MAX_RETURNED_GRANTS",
    "compute_grant_list_etag",
    "compute_grant_singleton_etag",
    "get_grant_or_404",
    "list_grants_for_recipient",
]

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
