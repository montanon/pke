"""``GET`` + ``POST /snapshots/{snapshot_id}/attestations`` endpoints.

* HLAM-70 — read: returns the list of witness attestations recorded for
  ``snapshot_id``, ordered by creation time ascending, with a stable
  ledger-derived ETag for recipient caches.
* HLAM-141 — write: capturer-side batch upload of witness attestations.
  Returns a per-item ``{accepted, rejected}`` envelope; the endpoint always
  returns 201 (the response itself carries per-item outcome). Domain rules
  live in :func:`pke_backend.services.attestations.create_attestations_batch`.

Path is on the snapshots resource per the Story; the module lives next to
its sibling attestation surfaces so the witness-attestation contract stays
grouped (mirror of the schemas/attestation.py / services/attestations.py
naming).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.db import get_session
from pke_backend.schemas.attestation import (
    AttestationBatchRequest,
    AttestationBatchResponse,
    WitnessAttestationListResponse,
    WitnessAttestationOut,
)
from pke_backend.security.dependencies import require_user
from pke_backend.services.attestations import (
    create_attestations_batch,
    list_attestations,
)
from pke_backend.services.snapshots import get_snapshot_or_404

__all__ = ["router"]

router = APIRouter(tags=["attestations"])


def _parse_snapshot_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPError(404, "snapshot_not_found", "snapshot_id is not a valid UUID") from exc


def _if_none_match_matches(header: str | None, etag: str) -> bool:
    if header is None:
        return False
    candidates = [v.strip() for v in header.split(",")]
    return any(v == etag or v == "*" for v in candidates)


@router.get(
    "/snapshots/{snapshot_id}/attestations",
    response_model=WitnessAttestationListResponse,
    responses={404: {"description": "snapshot_not_found"}},
)
async def get_snapshot_attestations(
    snapshot_id: str,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
) -> Response | WitnessAttestationListResponse:
    snapshot_uuid = _parse_snapshot_uuid(snapshot_id)
    await get_snapshot_or_404(session, snapshot_uuid)

    rows, ledger_hashes, etag = await list_attestations(session, snapshot_uuid)

    if _if_none_match_matches(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})

    response.headers["ETag"] = etag
    return WitnessAttestationListResponse(
        snapshot_id=str(snapshot_uuid),
        attestations=[
            WitnessAttestationOut.from_persisted(
                attestation=row,
                ledger_entry_hash=ledger_hash,
            )
            for row, ledger_hash in zip(rows, ledger_hashes, strict=True)
        ],
    )


@router.post(
    "/snapshots/{snapshot_id}/attestations",
    status_code=201,
    response_model=AttestationBatchResponse,
    dependencies=[Depends(require_user)],
    responses={
        401: {"description": "unauthenticated"},
        404: {"description": "snapshot_not_found"},
        422: {"description": "invalid_payload"},
    },
)
async def post_snapshot_attestations(
    snapshot_id: str,
    body: AttestationBatchRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AttestationBatchResponse:
    """Capturer-side batch upload — per-item verify + dedup + ledger anchor.

    The 50-item cap is enforced at the Pydantic layer
    (``AttestationBatchRequest.attestations`` has ``max_length=50``); an
    over-cap upload is rejected with 422 ``invalid_payload`` before any
    signature work happens. Per-item rejection reasons round-trip in the
    response envelope so clients can retry surgically rather than
    re-uploading the entire batch.
    """
    snapshot_uuid = _parse_snapshot_uuid(snapshot_id)
    return await create_attestations_batch(session, snapshot_uuid, body.attestations)
