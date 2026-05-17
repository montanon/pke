"""``GET /snapshots/{snapshot_id}/attestations`` endpoint (HLAM-70).

Returns the list of witness attestations recorded for ``snapshot_id``,
ordered by creation time ascending, with a stable ledger-derived ETag for
recipient caches.

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
    WitnessAttestationListResponse,
    WitnessAttestationOut,
)
from pke_backend.services.attestations import list_attestations
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
