"""Report service — verify, persist, and anchor a ``REPORTED`` ledger entry.

Called from :mod:`pke_backend.api.reports`. Pure-domain: no FastAPI imports.

Per ``context/04_protocol_overview.md`` a report is a metadata-level abuse /
legal / owner-request flag tied to a snapshot. The backend marks the snapshot
as reported and creates a ``REPORTED`` ledger entry — see HLAM-41 functional
requirements.

The signature on the report payload binds the reporter to the action; any
participant with a known public key may submit, per ``context/09_mvp_scope.md``
("basic report/freeze metadata action").

Transaction shape
-----------------

The flow is:

1. Parse identifiers; look up the snapshot; verify the signature. None of
   these write to the database, but the snapshot read autobegins a SQLAlchemy
   transaction. We ``rollback`` to release it before any later step that
   manages its own transaction.
2. INSERT the :class:`Report` row in its own short transaction. A UNIQUE
   collision on ``report_id`` surfaces as 409 ``report_id_conflict``. No
   ledger work has happened yet so a 409 here leaves the chain untouched.
3. Call :func:`pke_backend.services.ledger.append_entry`. The ledger
   service owns its own transaction (acquires the global advisory lock
   inside it) and dedups on ``(event_type, snapshot_id, payload_hash)``, so
   a retry of the same canonical payload is idempotent.

The "Report row first, ledger second" order means a hard failure between the
two commits leaves an orphan Report row without a ledger anchor. The reverse
order would leak orphan ledger entries on a UNIQUE collision, which is worse
(the ledger is the cryptographic source of truth and contains the entire
signed payload via ``payload_hash`` plus the wire-shape envelope hashed into
``entry_hash``). MVP accepts orphan-row risk.
"""

from __future__ import annotations

import logging
import uuid
from typing import cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.types import JsonValue
from pke_backend.models import EventType, LedgerEntry, Report
from pke_backend.protocol.ledger import LedgerEventType
from pke_backend.protocol.report_action import ReportAction
from pke_backend.services.ledger import append_entry
from pke_backend.services.signing import verify_action_signature
from pke_backend.services.snapshots import get_snapshot_or_404

__all__ = ["create_report", "list_reports_for_snapshot"]

logger = logging.getLogger(__name__)


def _parse_uuid(value: str, *, status: int, error_code: str, what: str) -> uuid.UUID:
    """Parse ``value`` as a UUID or raise an :class:`HTTPError`.

    ``snapshot_id`` non-UUID → 404 ``snapshot_not_found`` (a non-UUID can
    never resolve to an existing row, so 404 is the honest answer).
    ``report_id`` non-UUID → 422 ``invalid_payload``.

    Detail strings omit ``value`` to avoid echoing arbitrary client input
    back into the response.
    """
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPError(status, error_code, f"{what} is not a valid UUID") from exc


def _ledger_payload(action: ReportAction) -> dict[str, JsonValue]:
    """Return the canonical-body dict (action minus the signature field).

    The ledger service canonicalizes this dict to derive ``payload_hash``
    — exactly the bytes the signing device hashed and ECDSA covered.
    """
    body = action.to_json_value()
    if not isinstance(body, dict):  # pragma: no cover — Pydantic always returns dict
        raise TypeError("ReportAction.to_json_value() did not return a dict")
    body.pop("report_signature", None)
    return body


async def create_report(
    session: AsyncSession,
    action: ReportAction,
) -> tuple[Report, LedgerEntry]:
    """Verify ``action``, persist the report row, and append a ``REPORTED`` entry.

    Returns the (Report, LedgerEntry) pair so the API layer can build the
    response envelope.

    Raises:
        HTTPError(404, "snapshot_not_found", ...): snapshot id does not resolve.
        HTTPError(422, "invalid_payload", ...): report id is not a UUID.
        HTTPError(409, "report_id_conflict", ...): a report row with this
            ``report_id`` already exists.
        SignatureFormatError | SignatureVerificationError: handled at the
            global exception layer and mapped to 401.

    """
    snapshot_uuid = _parse_uuid(action.snapshot_id, status=404, error_code="snapshot_not_found", what="snapshot_id")
    report_uuid = _parse_uuid(action.report_id, status=422, error_code="invalid_payload", what="report_id")

    await get_snapshot_or_404(session, snapshot_uuid)
    verify_action_signature(
        action,
        signature_field="report_signature",
        public_key_field="reported_by_signing_public_key",
    )
    # Release the autobegun read-only transaction so the ledger service
    # can open its own (it asserts ``session.in_transaction() is False``).
    await session.rollback()

    report = Report(
        report_id=report_uuid,
        snapshot_id=snapshot_uuid,
        reason_category=action.reason_category,
        reported_by_signing_public_key=action.reported_by_signing_public_key,
        report_signature=action.report_signature,
    )
    session.add(report)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPError(409, "report_id_conflict", "report_id already exists") from exc

    entry = await append_entry(
        event_type=LedgerEventType.REPORTED,
        snapshot_id=snapshot_uuid,
        payload=_ledger_payload(action),
        version=action.version,
        session=session,
    )

    logger.info(
        "report_created snapshot_id=%s reason_category=%s",
        snapshot_uuid,
        action.reason_category.value,
    )
    return report, entry


def _etag_for_ledger_hashes(ledger_entry_hashes: list[bytes]) -> str:
    """Stable, sorted, canonical-bytes digest used as the GET list ETag.

    Quoted per RFC 7232; shared scheme with HLAM-70 / HLAM-75 (see those
    services' equivalents). Sorting + canonicalize is what makes the value
    replica-deterministic.
    """
    encoded = sorted(b64url_encode(h) for h in ledger_entry_hashes)
    digest = sha256(canonicalize(cast("JsonValue", encoded)))
    return f'"{digest.hex()}"'


async def list_reports_for_snapshot(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
) -> tuple[list[Report], list[bytes], str]:
    """Return ``(rows, ledger_entry_hashes, etag)`` for the GET list endpoint.

    Rows are ordered ``created_at ASC, id ASC`` (HLAM-82 AC #8). Ledger
    entries are fetched separately (``event_type=REPORTED``, same snapshot)
    ordered by ``id ASC`` — both lists are positionally paired since the
    POST handler writes each Report row and its REPORTED ledger entry in
    the same transaction (creation order is the join key).

    A length mismatch raises ``HTTPError(500, "report_ledger_inconsistent")``
    — defensive guard for an invariant the POST flow is responsible for.
    """
    rows_result = await session.execute(
        select(Report).where(Report.snapshot_id == snapshot_id).order_by(Report.created_at.asc(), Report.id.asc()),
    )
    rows = list(rows_result.scalars().all())

    ledger_result = await session.execute(
        select(LedgerEntry.entry_hash)
        .where(
            LedgerEntry.event_type == EventType.REPORTED,
            LedgerEntry.snapshot_id == snapshot_id,
        )
        .order_by(LedgerEntry.id.asc()),
    )
    ledger_hashes = list(ledger_result.scalars().all())

    if len(rows) != len(ledger_hashes):
        raise HTTPError(
            500,
            "report_ledger_inconsistent",
            f"report rows ({len(rows)}) and REPORTED ledger entries ({len(ledger_hashes)}) diverged for snapshot {snapshot_id}",
        )

    etag = _etag_for_ledger_hashes(ledger_hashes)
    return rows, ledger_hashes, etag
