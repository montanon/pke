"""Freeze service — verify, persist, and anchor a ``FROZEN`` ledger entry.

Called from :mod:`pke_backend.api.freezes`. Pure-domain: no FastAPI imports.

A freeze restricts future key grants for a reported snapshot. The freeze row
references a triggering report via FK (``ON DELETE RESTRICT``) and the
``UNIQUE(snapshot_id)`` constraint guarantees that each snapshot can be
frozen at most once.

This module also exposes :func:`is_snapshot_frozen` — the primitive that
``POST /key-grants`` (HLAM-74) and ``GET /snapshots/{id}`` (HLAM-80) will use
to honor AC #8 ("after a successful freeze, subsequent key-grants are
rejected"). The HLAM-79 surface ships the primitive + a unit test; the
endpoint wiring is HLAM-74/HLAM-80's responsibility.

Transaction shape (mirrors :mod:`pke_backend.services.reports`):

1. Parse identifiers; look up the snapshot + triggering report; verify the
   signature. Rollback the read-only autobegun transaction before any later
   step that manages its own.
2. INSERT the :class:`Freeze` row in its own short transaction.
   ``UNIQUE(snapshot_id)`` collisions surface as 409 ``snapshot_already_frozen``
   *before* any ledger work — this is what keeps the FROZEN chain clean
   under the concurrent-freeze case.
3. Call :func:`pke_backend.services.ledger.append_entry`. The ledger
   service owns its own transaction and dedups on
   ``(event_type, snapshot_id, payload_hash)``; retries are idempotent.
"""

from __future__ import annotations

import logging
import uuid
from typing import cast

from sqlalchemy import literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.types import JsonValue
from pke_backend.models import EventType, Freeze, LedgerEntry, Report
from pke_backend.protocol.freeze import FreezeAction
from pke_backend.protocol.ledger import LedgerEventType
from pke_backend.services.ledger import append_entry
from pke_backend.services.signing import verify_action_signature
from pke_backend.services.snapshots import get_snapshot_or_404

__all__ = [
    "create_freeze",
    "is_snapshot_frozen",
    "list_freezes_for_snapshot",
]

logger = logging.getLogger(__name__)


def _parse_snapshot_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPError(404, "snapshot_not_found", "snapshot_id is not a valid UUID") from exc


def _parse_triggered_by(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPError(
            422,
            "triggered_by_report_not_found",
            "triggered_by is not a valid UUID",
        ) from exc


def _parse_freeze_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPError(422, "invalid_payload", "freeze_id is not a valid UUID") from exc


def _ledger_payload(action: FreezeAction) -> dict[str, JsonValue]:
    """Return the canonical-body dict (action minus the signature field)."""
    body = action.to_json_value()
    if not isinstance(body, dict):  # pragma: no cover
        raise TypeError("FreezeAction.to_json_value() did not return a dict")
    body.pop("freeze_signature", None)
    return body


async def create_freeze(
    session: AsyncSession,
    action: FreezeAction,
) -> tuple[Freeze, LedgerEntry]:
    """Verify ``action``, persist the freeze row, and append a ``FROZEN`` entry.

    Returns the (Freeze, LedgerEntry) pair so the API layer can build the
    response envelope.

    Raises:
        HTTPError(404, "snapshot_not_found", ...): snapshot id does not resolve.
        HTTPError(422, "triggered_by_report_not_found", ...): the cited report
            id does not exist (or is not a valid UUID).
        HTTPError(409, "snapshot_already_frozen", ...): a freeze for this
            snapshot already exists (``UNIQUE(snapshot_id)`` collision).
        SignatureFormatError | SignatureVerificationError: handled by the
            global exception layer → 401.

    """
    snapshot_uuid = _parse_snapshot_uuid(action.snapshot_id)
    triggered_uuid = _parse_triggered_by(action.triggered_by)
    freeze_uuid = _parse_freeze_uuid(action.freeze_id)

    await get_snapshot_or_404(session, snapshot_uuid)

    report = await session.scalar(select(Report).where(Report.report_id == triggered_uuid))
    if report is None:
        await session.rollback()
        raise HTTPError(
            422,
            "triggered_by_report_not_found",
            f"report {triggered_uuid} not found",
        )

    verify_action_signature(
        action,
        signature_field="freeze_signature",
        public_key_field="frozen_by_signing_public_key",
    )
    # Release the read-only tx so the ledger service can open its own.
    await session.rollback()

    freeze = Freeze(
        freeze_id=freeze_uuid,
        snapshot_id=snapshot_uuid,
        triggered_by_report_id=triggered_uuid,
        freeze_signature=action.freeze_signature,
    )
    session.add(freeze)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        # Only ``uq_freezes_snapshot_id`` or ``uq_freezes_freeze_id`` can
        # fire here; both reduce to "this snapshot can no longer be frozen
        # under this id" from the client's perspective.
        raise HTTPError(
            409,
            "snapshot_already_frozen",
            f"snapshot {snapshot_uuid} is already frozen",
        ) from exc

    entry = await append_entry(
        event_type=LedgerEventType.FROZEN,
        snapshot_id=snapshot_uuid,
        payload=_ledger_payload(action),
        version=action.version,
        session=session,
    )

    logger.info("freeze_created snapshot_id=%s triggered_by=%s", snapshot_uuid, triggered_uuid)
    return freeze, entry


async def is_snapshot_frozen(session: AsyncSession, snapshot_id: uuid.UUID) -> bool:
    """Return ``True`` iff a freeze row exists for ``snapshot_id``.

    Primitive consumed by ``POST /key-grants`` (HLAM-74) and the frozen-flag
    propagation work in HLAM-80. AC #8 ("subsequent key-grants rejected with
    409 snapshot_frozen") is gated on those stories; HLAM-79 ships only this
    helper and its unit test.
    """
    found = await session.scalar(
        select(literal(True)).where(Freeze.snapshot_id == snapshot_id).limit(1),
    )
    return bool(found)


def _etag_for_ledger_hashes(ledger_entry_hashes: list[bytes]) -> str:
    """Same canonical-bytes ETag scheme as the reports/attestations endpoints."""
    encoded = sorted(b64url_encode(h) for h in ledger_entry_hashes)
    digest = sha256(canonicalize(cast("JsonValue", encoded)))
    return f'"{digest.hex()}"'


async def list_freezes_for_snapshot(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
) -> tuple[list[Freeze], list[bytes], str]:
    """Return ``(rows, ledger_entry_hashes, etag)`` for HLAM-82 AC #9.

    UNIQUE(snapshot_id) means there is at most one freeze per snapshot, so
    the lists hold zero or one entry. The envelope shape stays list-shaped
    so future schema bumps (e.g. soft-deleted re-freezes) don't break wire
    compatibility.

    Length mismatch → ``HTTPError(500, "freeze_ledger_inconsistent")``.
    """
    rows_result = await session.execute(
        select(Freeze).where(Freeze.snapshot_id == snapshot_id).order_by(Freeze.created_at.asc(), Freeze.id.asc()),
    )
    rows = list(rows_result.scalars().all())

    ledger_result = await session.execute(
        select(LedgerEntry.entry_hash)
        .where(
            LedgerEntry.event_type == EventType.FROZEN,
            LedgerEntry.snapshot_id == snapshot_id,
        )
        .order_by(LedgerEntry.id.asc()),
    )
    ledger_hashes = list(ledger_result.scalars().all())

    if len(rows) != len(ledger_hashes):
        raise HTTPError(
            500,
            "freeze_ledger_inconsistent",
            f"freeze rows ({len(rows)}) and FROZEN ledger entries ({len(ledger_hashes)}) diverged for snapshot {snapshot_id}",
        )

    etag = _etag_for_ledger_hashes(ledger_hashes)
    return rows, ledger_hashes, etag
