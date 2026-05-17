"""``GET /snapshots/{snapshot_id}`` + ``/blob`` endpoints (HLAM-65).

Two routes share this module:

* ``GET /snapshots/{snapshot_id}`` returns a :class:`SnapshotOut` envelope:
  commitment metadata + ``blob_url`` + ``ledger_entry_hash`` + ``frozen`` flag.
* ``GET /snapshots/{snapshot_id}/blob`` (also accepts HEAD) streams the
  opaque ciphertext blob persisted at POST time, honouring ``If-None-Match``
  for cache-friendly recipients and a single-form ``Range`` header for
  resumable downloads.

HLAM-82 layers two more list routes on the same router:
``/snapshots/{snapshot_id}/reports`` and ``/snapshots/{snapshot_id}/freezes``.

Per ``context/08_security_assumptions.md`` the blob is opaque ciphertext —
no auth required. Error envelopes flow through
:mod:`pke_backend.api.errors`.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.crypto.encoding import hex_encode
from pke_backend.db import get_session
from pke_backend.schemas.freezes import FreezeOut, FreezesListResponse
from pke_backend.schemas.reports import ReportOut, ReportsListResponse
from pke_backend.schemas.snapshot import SnapshotOut
from pke_backend.services.blob_storage import (
    BlobNotFoundError,
    BlobStoreError,
    FilesystemBlobStore,
    get_blob_store,
)
from pke_backend.services.freezes import list_freezes_for_snapshot
from pke_backend.services.reports import list_reports_for_snapshot
from pke_backend.services.snapshots import (
    fetch_snapshot_for_response,
    get_snapshot_or_404,
)

__all__ = ["router"]

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/snapshots", tags=["snapshots"])

_CONTENT_TYPE_OCTET_STREAM: Final[str] = "application/octet-stream"
_RANGE_RE: Final[re.Pattern[str]] = re.compile(r"^bytes=(\d+)-(\d*)$")


def _parse_snapshot_uuid(value: str) -> uuid.UUID:
    """Reject non-UUID path params as 404 — they cannot resolve to a row."""
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPError(404, "snapshot_not_found", "snapshot_id is not a valid UUID") from exc


def _etag_for_ciphertext_hash(ciphertext_hash: bytes) -> str:
    """Strong ETag (hex of the blob's SHA-256), quoted per RFC 7232."""
    return f'"{hex_encode(ciphertext_hash)}"'


def _if_none_match_matches(header: str | None, etag: str) -> bool:
    """RFC 7232: ``If-None-Match: <etag>`` or ``*`` short-circuits to 304."""
    if header is None:
        return False
    candidates = [v.strip() for v in header.split(",")]
    return any(v == etag or v == "*" for v in candidates)


@router.get(
    "/{snapshot_id}",
    response_model=SnapshotOut,
    responses={
        404: {"description": "snapshot_not_found"},
        500: {"description": "ledger_entry_missing"},
    },
)
async def get_snapshot(
    snapshot_id: str,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SnapshotOut:
    snapshot_uuid = _parse_snapshot_uuid(snapshot_id)
    snapshot, ledger_entry_hash, frozen = await fetch_snapshot_for_response(session, snapshot_uuid)
    return SnapshotOut.from_persisted(snapshot, ledger_entry_hash, frozen=frozen)


def _parse_range_header(header: str, size: int) -> tuple[int, int]:
    """Return ``(start, length)`` for a single-range bytes form, or raise 416.

    Accepted forms:
        ``bytes=N-M`` (N inclusive, M inclusive; ``M < size``)
        ``bytes=N-``  (N to end-of-blob)

    All other forms (multi-range, suffix-byte ``bytes=-N``, non-numeric, or
    invalid endpoints) → 416 ``range_not_satisfiable``.
    """
    match = _RANGE_RE.match(header)
    if match is None:
        raise HTTPError(416, "range_not_satisfiable", "unsupported Range form")
    start_str, end_str = match.group(1), match.group(2)
    start = int(start_str)
    if start >= size:
        raise HTTPError(416, "range_not_satisfiable", "Range start beyond blob size")
    if end_str == "":
        end_inclusive = size - 1
    else:
        end_inclusive = int(end_str)
        if end_inclusive < start or end_inclusive >= size:
            raise HTTPError(416, "range_not_satisfiable", "Range end invalid")
    length = end_inclusive - start + 1
    return start, length


async def _handle_blob_request(
    *,
    request: Request,
    session: AsyncSession,
    blob_store: FilesystemBlobStore,
    snapshot_id_str: str,
    if_none_match: str | None,
    range_header: str | None,
) -> Response:
    snapshot_uuid = _parse_snapshot_uuid(snapshot_id_str)
    snapshot = await get_snapshot_or_404(session, snapshot_uuid)

    etag = _etag_for_ciphertext_hash(snapshot.ciphertext_hash)

    if _if_none_match_matches(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})

    try:
        size = await blob_store.size(snapshot_uuid)
    except BlobNotFoundError:
        logger.error("blob_storage_inconsistent snapshot_id=%s", snapshot_uuid)
        raise HTTPError(500, "blob_storage_inconsistent", "blob row exists but file missing") from None
    except BlobStoreError as exc:
        logger.error("blob_store_io_error snapshot_id=%s reason=%s", snapshot_uuid, exc.reason)
        raise HTTPError(500, "blob_storage_inconsistent", "blob storage I/O error") from exc

    base_headers = {
        "ETag": etag,
        "Accept-Ranges": "bytes",
    }

    if range_header is not None:
        try:
            start, length = _parse_range_header(range_header, size)
        except HTTPError as exc:
            # 416 must carry ``Content-Range: bytes */<size>`` per RFC 7233.
            exc_headers = {"Content-Range": f"bytes */{size}", **base_headers}
            return Response(
                status_code=416,
                content=f'{{"error": "{exc.error}", "detail": "{exc.detail}"}}',
                media_type="application/json",
                headers=exc_headers,
            )
        headers = {
            **base_headers,
            "Content-Length": str(length),
            "Content-Range": f"bytes {start}-{start + length - 1}/{size}",
        }
        if request.method == "HEAD":
            return Response(status_code=206, headers=headers, media_type=_CONTENT_TYPE_OCTET_STREAM)
        return StreamingResponse(
            blob_store.get_range(snapshot_uuid, offset=start, length=length),
            status_code=206,
            media_type=_CONTENT_TYPE_OCTET_STREAM,
            headers=headers,
        )

    headers = {**base_headers, "Content-Length": str(size)}
    if request.method == "HEAD":
        return Response(status_code=200, headers=headers, media_type=_CONTENT_TYPE_OCTET_STREAM)
    return StreamingResponse(
        blob_store.get(snapshot_uuid),
        media_type=_CONTENT_TYPE_OCTET_STREAM,
        headers=headers,
    )


@router.get("/{snapshot_id}/blob")
async def get_snapshot_blob(
    snapshot_id: str,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    blob_store: Annotated[FilesystemBlobStore, Depends(get_blob_store)],
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
    range_header: Annotated[str | None, Header(alias="Range")] = None,
) -> Response:
    return await _handle_blob_request(
        request=request,
        session=session,
        blob_store=blob_store,
        snapshot_id_str=snapshot_id,
        if_none_match=if_none_match,
        range_header=range_header,
    )


@router.head("/{snapshot_id}/blob")
async def head_snapshot_blob(
    snapshot_id: str,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    blob_store: Annotated[FilesystemBlobStore, Depends(get_blob_store)],
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
    range_header: Annotated[str | None, Header(alias="Range")] = None,
) -> Response:
    return await _handle_blob_request(
        request=request,
        session=session,
        blob_store=blob_store,
        snapshot_id_str=snapshot_id,
        if_none_match=if_none_match,
        range_header=range_header,
    )


@router.get(
    "/{snapshot_id}/reports",
    response_model=ReportsListResponse,
    responses={404: {"description": "snapshot_not_found"}},
)
async def list_snapshot_reports(
    snapshot_id: str,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
) -> Response | ReportsListResponse:
    """Return all reports for ``snapshot_id`` in ``created_at ASC`` order (HLAM-82 AC #8)."""
    snapshot_uuid = _parse_snapshot_uuid(snapshot_id)
    await get_snapshot_or_404(session, snapshot_uuid)

    rows, ledger_hashes, etag = await list_reports_for_snapshot(session, snapshot_uuid)

    if _if_none_match_matches(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})

    response.headers["ETag"] = etag
    return ReportsListResponse(
        snapshot_id=str(snapshot_uuid),
        reports=[
            ReportOut.from_persisted(row, ledger_entry_hash=ledger_hash)
            for row, ledger_hash in zip(rows, ledger_hashes, strict=True)
        ],
    )


@router.get(
    "/{snapshot_id}/freezes",
    response_model=FreezesListResponse,
    responses={404: {"description": "snapshot_not_found"}},
)
async def list_snapshot_freezes(
    snapshot_id: str,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
) -> Response | FreezesListResponse:
    """Return the (at most one) freeze for ``snapshot_id`` (HLAM-82 AC #9)."""
    snapshot_uuid = _parse_snapshot_uuid(snapshot_id)
    await get_snapshot_or_404(session, snapshot_uuid)

    rows, ledger_hashes, etag = await list_freezes_for_snapshot(session, snapshot_uuid)

    if _if_none_match_matches(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})

    response.headers["ETag"] = etag
    return FreezesListResponse(
        snapshot_id=str(snapshot_uuid),
        freezes=[
            FreezeOut.from_persisted(row, ledger_entry_hash=ledger_hash)
            for row, ledger_hash in zip(rows, ledger_hashes, strict=True)
        ],
    )
