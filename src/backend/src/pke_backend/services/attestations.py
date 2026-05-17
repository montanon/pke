"""Witness-attestation service helpers.

* HLAM-70 — read path (``GET /snapshots/{id}/attestations``): :func:`list_attestations`.
* HLAM-141 — write path (``POST /snapshots/{id}/attestations``):
  :func:`create_attestations_batch`. Capturer-side batch upload with per-item
  signature verification, intra-batch + persisted-row dedup on
  ``(snapshot_id, witness_signing_public_key)``, and one ``WITNESS_ATTESTED``
  ledger entry per accepted attestation. The endpoint always returns 201 and
  reports per-item outcome in a ``{accepted, rejected}`` response envelope.

Pure-domain: no FastAPI imports. The endpoints translate the helpers' return
values into HTTP response envelopes.

Attestations are paired with their ``WITNESS_ATTESTED`` ledger entry by
**creation order**: both rows are written in the same transaction, so
``id ASC`` on each table is the natural join key. A future schema bump can
add a ``ledger_entry_hash`` FK column to ``witness_attestations`` and the
join collapses to one query — the positional pairing is the MVP shape, not
the long-term contract.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from typing import Final, cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import SignatureFormatError, SignatureVerificationError
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.signatures import verify_signature
from pke_backend.crypto.types import JsonValue
from pke_backend.models import EventType, LedgerEntry, WitnessAttestation
from pke_backend.models.attestation import WITNESS_ATTESTATION_VERSION
from pke_backend.protocol.ledger import LedgerEventType
from pke_backend.schemas.attestation import (
    AcceptedAttestation,
    AttestationBatchResponse,
    AttestationRejectionReason,
    RejectedAttestation,
    WitnessAttestationIn,
)
from pke_backend.services.ledger import append_entry
from pke_backend.services.signing import load_p256_public_key
from pke_backend.services.snapshots import get_snapshot_or_404

__all__ = [
    "MAX_RETURNED_ATTESTATIONS",
    "compute_attestation_etag",
    "create_attestations_batch",
    "list_attestations",
]

logger = logging.getLogger(__name__)

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


def _verify_item_signature(item: WitnessAttestationIn) -> bool:
    """Return ``True`` iff ``item``'s ECDSA-P256 witness signature verifies.

    Wraps :func:`pke_backend.crypto.signatures.verify_signature` with the
    canonical-bytes builder already on the Pydantic model. Returns ``False``
    on either format errors (bad pubkey or signature length / curve) or
    verification failures — both reduce to the single
    :data:`AttestationRejectionReason.SIGNATURE_INVALID` rejection at the
    batch boundary.
    """
    try:
        public_key = load_p256_public_key(item.witness_signing_public_key)
        verify_signature(public_key, item.canonical_body_bytes(), item.witness_signature)
    except (SignatureFormatError, SignatureVerificationError):
        return False
    return True


def _ledger_payload_for_attestation(item: WitnessAttestationIn) -> dict[str, JsonValue]:
    """Return the canonical-body dict (item minus the witness signature).

    The ledger service canonicalizes this dict to derive ``payload_hash`` —
    exactly the bytes the witness device hashed and ECDSA covered. Stable
    by construction: ``dump_exclude_signature`` excludes ``witness_signature``
    and the canonicalizer downstream sorts keys.
    """
    body = item.dump_exclude_signature()
    if not isinstance(body, dict):  # pragma: no cover — Pydantic always returns dict
        raise TypeError("WitnessAttestationIn.dump_exclude_signature() did not return a dict")
    return body


async def create_attestations_batch(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
    attestations: Sequence[WitnessAttestationIn],
) -> AttestationBatchResponse:
    """Verify and persist a batch of witness attestations for ``snapshot_id``.

    Always returns 201 — the response envelope reports per-item accept /
    reject outcomes. The endpoint's only hard-failure paths are 404 (unknown
    snapshot) and 422 (payload schema or batch-cap violation, both caught
    upstream by Pydantic).

    Flow:
        1. ``get_snapshot_or_404(session, snapshot_id)`` — 404 if unknown.
        2. Pre-query existing ``witness_signing_public_key`` strings for the
           snapshot. Used to short-circuit duplicates before signature work.
        3. Walk the request list once. Per item: snapshot-mismatch first
           (cheapest), then version, then signature verify, then dedup
           against persisted + in-batch sets. Accepted items go to one list,
           rejections to another; both preserve the request's index order.
        4. Bulk-INSERT accepted rows in a single transaction. On
           ``IntegrityError`` (a concurrent batch raced us through the
           pre-query TOCTOU window), re-query the persisted dedup set,
           downgrade now-colliding items to ``duplicate_witness_key``, and
           commit the survivors. The retry is bounded to one round-trip.
        5. Per accepted row: one ``append_entry(WITNESS_ATTESTED, ...)``
           call. The ledger service serialises via Postgres advisory lock,
           so concurrent batches still produce a strictly linear chain.

    Returns:
        :class:`AttestationBatchResponse` with index-aligned
        ``accepted`` / ``rejected`` lists.

    Raises:
        HTTPError(404, "snapshot_not_found", ...): no row for ``snapshot_id``.

    """
    await get_snapshot_or_404(session, snapshot_id)
    # Release the autobegun read transaction so the bulk-INSERT below can
    # own its own transaction. (Mirrors :mod:`pke_backend.services.reports`.)
    await session.rollback()

    persisted_keys = await _fetch_persisted_witness_keys(session, snapshot_id)

    accepted_inputs, rejections = _classify_batch(
        snapshot_id=snapshot_id,
        attestations=attestations,
        persisted_keys=persisted_keys,
    )

    persisted_rows, extra_rejections = await _persist_accepted_rows(
        session=session,
        snapshot_id=snapshot_id,
        accepted_inputs=accepted_inputs,
    )
    rejections.extend(extra_rejections)

    accepted: list[AcceptedAttestation] = []
    for index, item, row in persisted_rows:
        entry = await append_entry(
            event_type=LedgerEventType.WITNESS_ATTESTED,
            snapshot_id=snapshot_id,
            payload=_ledger_payload_for_attestation(item),
            version=item.version,
            session=session,
        )
        accepted.append(
            AcceptedAttestation(
                index=index,
                witness_signing_public_key=row.witness_signing_public_key,
                ledger_entry_id=entry.ledger_entry_id,
                ledger_entry_hash=b64url_encode(entry.entry_hash),
            ),
        )

    # Sort rejections back into request-position order; per-item processing
    # may interleave intra-batch dedup, post-commit downgrades, etc.
    rejections.sort(key=lambda r: r.index)

    logger.info(
        "attestations_batch_created snapshot_id=%s accepted=%d rejected=%d",
        snapshot_id,
        len(accepted),
        len(rejections),
    )

    return AttestationBatchResponse(
        snapshot_id=snapshot_id,
        accepted=accepted,
        rejected=rejections,
    )


async def _fetch_persisted_witness_keys(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
) -> set[str]:
    """Return the set of ``witness_signing_public_key`` strings already on file.

    Strings, not bytes — the ORM column is ``Text`` (base64url-encoded), so
    we compare against b64url-encoded candidates in the request walk.
    """
    stmt = select(WitnessAttestation.witness_signing_public_key).where(
        WitnessAttestation.snapshot_id == snapshot_id,
    )
    result = await session.execute(stmt)
    return set(result.scalars().all())


def _classify_batch(
    *,
    snapshot_id: uuid.UUID,
    attestations: Sequence[WitnessAttestationIn],
    persisted_keys: set[str],
) -> tuple[list[tuple[int, WitnessAttestationIn, str]], list[RejectedAttestation]]:
    """Walk the request list once; return ``(accepted_inputs, rejections)``.

    ``accepted_inputs`` carries ``(index, item, witness_key_b64)`` tuples so
    the persistence step can rebuild rows without re-encoding the pubkey.
    """
    snapshot_id_str = str(snapshot_id)
    accepted_inputs: list[tuple[int, WitnessAttestationIn, str]] = []
    rejections: list[RejectedAttestation] = []
    seen_in_batch: set[str] = set()

    for index, item in enumerate(attestations):
        witness_key_b64 = b64url_encode(item.witness_signing_public_key)

        if item.snapshot_id != snapshot_id_str:
            rejections.append(
                RejectedAttestation(
                    index=index,
                    witness_signing_public_key=witness_key_b64,
                    reason=AttestationRejectionReason.SNAPSHOT_MISMATCH,
                ),
            )
            continue

        if item.version != WITNESS_ATTESTATION_VERSION:
            rejections.append(
                RejectedAttestation(
                    index=index,
                    witness_signing_public_key=witness_key_b64,
                    reason=AttestationRejectionReason.VERSION_UNSUPPORTED,
                ),
            )
            continue

        if witness_key_b64 in persisted_keys or witness_key_b64 in seen_in_batch:
            rejections.append(
                RejectedAttestation(
                    index=index,
                    witness_signing_public_key=witness_key_b64,
                    reason=AttestationRejectionReason.DUPLICATE_WITNESS_KEY,
                ),
            )
            continue

        if not _verify_item_signature(item):
            rejections.append(
                RejectedAttestation(
                    index=index,
                    witness_signing_public_key=witness_key_b64,
                    reason=AttestationRejectionReason.SIGNATURE_INVALID,
                ),
            )
            continue

        seen_in_batch.add(witness_key_b64)
        accepted_inputs.append((index, item, witness_key_b64))

    return accepted_inputs, rejections


def _build_attestation_row(
    *,
    snapshot_id: uuid.UUID,
    item: WitnessAttestationIn,
    witness_key_b64: str,
) -> WitnessAttestation:
    return WitnessAttestation(
        snapshot_id=snapshot_id,
        witness_signing_public_key=witness_key_b64,
        witness_timestamp=item.witness_timestamp,
        transport=item.transport,
        proximity_claim=cast("dict[str, JsonValue]", item.proximity_claim.model_dump(mode="json")),
        witness_signature=item.witness_signature,
        version=item.version,
    )


async def _persist_accepted_rows(
    *,
    session: AsyncSession,
    snapshot_id: uuid.UUID,
    accepted_inputs: list[tuple[int, WitnessAttestationIn, str]],
) -> tuple[list[tuple[int, WitnessAttestationIn, WitnessAttestation]], list[RejectedAttestation]]:
    """Bulk-INSERT the accepted rows; on TOCTOU race, retry the survivors.

    Returns ``(persisted_rows, extra_rejections)``. ``persisted_rows`` carries
    ``(index, item, row)`` tuples in the order they were committed so the
    caller can chain a ledger append per row. ``extra_rejections`` covers
    items that lost a race with a concurrent batch and were downgraded to
    ``duplicate_witness_key`` post-commit.

    The retry is bounded to a single round-trip: if a second collision were
    to fire after the requery, that would imply yet another concurrent
    batch arrived after the requery — vanishingly unlikely in practice, and
    the next attestation POST against the same snapshot will surface the
    collision deterministically.
    """
    if not accepted_inputs:
        return [], []

    rows = [
        _build_attestation_row(snapshot_id=snapshot_id, item=item, witness_key_b64=key)
        for _index, item, key in accepted_inputs
    ]
    session.add_all(rows)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return await _retry_after_concurrent_collision(
            session=session,
            snapshot_id=snapshot_id,
            accepted_inputs=accepted_inputs,
        )

    persisted_rows = [(index, item, row) for (index, item, _key), row in zip(accepted_inputs, rows, strict=True)]
    return persisted_rows, []


async def _retry_after_concurrent_collision(
    *,
    session: AsyncSession,
    snapshot_id: uuid.UUID,
    accepted_inputs: list[tuple[int, WitnessAttestationIn, str]],
) -> tuple[list[tuple[int, WitnessAttestationIn, WitnessAttestation]], list[RejectedAttestation]]:
    """Re-query the persisted dedup set and commit only the survivors.

    Called after a first INSERT raised ``IntegrityError`` — a concurrent
    batch raced through our pre-query's TOCTOU window. We re-fetch the
    persisted keys, drop the collided inputs into ``extra_rejections``, and
    INSERT the rest. A second ``IntegrityError`` here is treated as an
    unrecoverable contention spike and surfaces as 500 to the caller —
    realistically this would require a third batch arriving in the
    sub-millisecond window between requery and commit.
    """
    persisted_keys_now = await _fetch_persisted_witness_keys(session, snapshot_id)
    await session.rollback()

    survivors: list[tuple[int, WitnessAttestationIn, str]] = []
    extra_rejections: list[RejectedAttestation] = []
    for index, item, key in accepted_inputs:
        if key in persisted_keys_now:
            extra_rejections.append(
                RejectedAttestation(
                    index=index,
                    witness_signing_public_key=key,
                    reason=AttestationRejectionReason.DUPLICATE_WITNESS_KEY,
                ),
            )
        else:
            survivors.append((index, item, key))

    if not survivors:
        return [], extra_rejections

    rows = [
        _build_attestation_row(snapshot_id=snapshot_id, item=item, witness_key_b64=key)
        for _index, item, key in survivors
    ]
    session.add_all(rows)
    try:
        await session.commit()
    except IntegrityError as exc:  # pragma: no cover — third concurrent writer in microseconds
        await session.rollback()
        raise HTTPError(
            500,
            "attestation_persist_contention",
            f"snapshot {snapshot_id}: repeated concurrent writes for the same witness pubkeys",
        ) from exc

    persisted_rows = [(index, item, row) for (index, item, _key), row in zip(survivors, rows, strict=True)]
    return persisted_rows, extra_rejections
