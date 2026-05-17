"""Witness-attestation read helpers — backs HLAM-70 ``GET /snapshots/{id}/attestations``.

Pure-domain: no FastAPI imports. The endpoint translates the helper's
return value into the response envelope.

Attestations are paired with their ``WITNESS_ATTESTED`` ledger entry by
**creation order**: both rows are written in the same POST transaction, so
``id ASC`` on each table is the natural join key. A future schema bump can
add a ``ledger_entry_hash`` FK column to ``witness_attestations`` and the
join collapses to one query — the positional pairing is the MVP shape, not
the long-term contract.
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
from pke_backend.models import EventType, LedgerEntry, WitnessAttestation

__all__ = [
    "MAX_RETURNED_ATTESTATIONS",
    "compute_attestation_etag",
    "list_attestations",
]

MAX_RETURNED_ATTESTATIONS: Final[int] = 500


def compute_attestation_etag(ledger_entry_hashes: Sequence[bytes]) -> str:
    """Stable, sorted, canonical-bytes digest used as the GET list ETag.

    Encoded as quoted hex per RFC 7232. Sorting + canonicalize is what
    makes the value replica-deterministic across the F6 verification
    report; HLAM-77 imports this helper to reproduce the same digest.
    """
    encoded = sorted(b64url_encode(h) for h in ledger_entry_hashes)
    digest = sha256(canonicalize(cast("JsonValue", encoded)))
    return f'"{digest.hex()}"'


async def list_attestations(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
) -> tuple[list[WitnessAttestation], list[bytes], str]:
    """Return ``(rows, ledger_entry_hashes, etag)`` for the GET list endpoint.

    Caller is responsible for the ``snapshot_not_found`` 404 — this helper
    does not check snapshot existence (it returns an empty list when no
    attestations exist, which is HLAM-70 AC #2). The endpoint pairs both
    checks with :func:`pke_backend.services.snapshots.get_snapshot_or_404`.

    Raises:
        HTTPError(413, "attestation_list_too_large", ...): more than
            :data:`MAX_RETURNED_ATTESTATIONS` rows exist for the snapshot —
            documented cap from the Story's Edge Cases.
        HTTPError(500, "attestation_ledger_inconsistent", ...): the row
            count and WITNESS_ATTESTED ledger-entry count diverge.
            Defensive guard; the POST flow writes both in the same tx.

    """
    rows_stmt = (
        select(WitnessAttestation)
        .where(WitnessAttestation.snapshot_id == snapshot_id)
        .order_by(WitnessAttestation.created_at.asc(), WitnessAttestation.id.asc())
        .limit(MAX_RETURNED_ATTESTATIONS + 1)
    )
    rows_result = await session.execute(rows_stmt)
    rows = list(rows_result.scalars().all())
    if len(rows) > MAX_RETURNED_ATTESTATIONS:
        raise HTTPError(
            413,
            "attestation_list_too_large",
            f"snapshot has more than {MAX_RETURNED_ATTESTATIONS} attestations",
        )

    ledger_stmt = (
        select(LedgerEntry.entry_hash)
        .where(
            LedgerEntry.event_type == EventType.WITNESS_ATTESTED,
            LedgerEntry.snapshot_id == snapshot_id,
        )
        .order_by(LedgerEntry.id.asc())
    )
    ledger_result = await session.execute(ledger_stmt)
    ledger_hashes = list(ledger_result.scalars().all())

    if len(rows) != len(ledger_hashes):
        raise HTTPError(
            500,
            "attestation_ledger_inconsistent",
            f"attestation rows ({len(rows)}) and WITNESS_ATTESTED ledger entries ({len(ledger_hashes)}) diverged for snapshot {snapshot_id}",
        )

    etag = compute_attestation_etag(ledger_hashes)
    return rows, ledger_hashes, etag
