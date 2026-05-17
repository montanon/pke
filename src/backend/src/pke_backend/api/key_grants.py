"""``GET /key-grants/{grant_id}`` + ``GET /key-grants`` endpoints (HLAM-75).

Recipient-facing read surface. Two routes:

* ``GET /key-grants/{grant_id}`` — single grant by primary identifier.
* ``GET /key-grants?recipient_encryption_public_key=<b64url>`` — all grants
  addressed to the recipient pubkey, newest first.

Both routes are read-only and unauthenticated per
``context/05_data_model_public.md``: the wrapped key bytes are encrypted
to the recipient, so even an exhaustive scrape only yields ciphertext the
recipient's device can decrypt.
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.api.errors import HTTPError
from pke_backend.crypto.encoding import b64url_decode, b64url_encode
from pke_backend.crypto.errors import EncodingError
from pke_backend.db import get_session
from pke_backend.schemas.key_grant import (
    RECIPIENT_PUBLIC_KEY_BYTES,
    KeyGrantListResponse,
    KeyGrantOut,
)
from pke_backend.services.key_grants import (
    compute_grant_singleton_etag,
    get_grant_or_404,
    list_grants_for_recipient,
)

__all__ = ["router"]

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/key-grants", tags=["key_grants"])

_RECIPIENT_PUBKEY_DESCRIPTION: Final[str] = (
    "Recipient encryption public key (uncompressed P-256, base64url-no-pad, 87 chars)."
)


def _parse_grant_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPError(404, "grant_not_found", "grant_id is not a valid UUID") from exc


def _validate_recipient_pubkey(value: str) -> str:
    """Reject malformed recipient pubkey query params with 400.

    Returns the canonicalised base64url-no-pad string. Detail strings carry
    byte counts only — never the raw value — per the HLAM-79 info-disclosure
    discipline.
    """
    try:
        decoded = b64url_decode(value)
    except EncodingError as exc:
        raise HTTPError(
            400,
            "invalid_recipient_pubkey",
            "recipient_encryption_public_key is not valid base64url-no-pad",
        ) from exc
    if len(decoded) != RECIPIENT_PUBLIC_KEY_BYTES:
        raise HTTPError(
            400,
            "invalid_recipient_pubkey",
            f"recipient_encryption_public_key must decode to {RECIPIENT_PUBLIC_KEY_BYTES} bytes",
        )
    # Re-encode to canonicalise (e.g. strip incidental padding that decoded
    # under a permissive client). DB stores the canonical no-pad form.
    return b64url_encode(decoded)


def _if_none_match_matches(header: str | None, etag: str) -> bool:
    if header is None:
        return False
    candidates = [v.strip() for v in header.split(",")]
    return any(v == etag or v == "*" for v in candidates)


@router.get(
    "/{grant_id}",
    response_model=KeyGrantOut,
    responses={
        404: {"description": "grant_not_found"},
        500: {"description": "grant_ledger_inconsistent"},
    },
)
async def get_key_grant(
    grant_id: str,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
) -> Response | KeyGrantOut:
    grant_uuid = _parse_grant_uuid(grant_id)
    grant, ledger_hash = await get_grant_or_404(session, grant_uuid)
    etag = compute_grant_singleton_etag(ledger_hash)
    if _if_none_match_matches(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    return KeyGrantOut.from_persisted(grant, ledger_hash)


@router.get(
    "",
    response_model=KeyGrantListResponse,
    responses={
        400: {"description": "invalid_recipient_pubkey"},
        413: {"description": "grant_list_too_large"},
    },
)
async def list_key_grants(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
    recipient_encryption_public_key: Annotated[
        str,
        Query(min_length=1, description=_RECIPIENT_PUBKEY_DESCRIPTION),
    ],
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
) -> Response | KeyGrantListResponse:
    canonical_pubkey = _validate_recipient_pubkey(recipient_encryption_public_key)
    rows, ledger_hashes, etag = await list_grants_for_recipient(session, canonical_pubkey)
    if _if_none_match_matches(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    return KeyGrantListResponse(
        recipient_encryption_public_key=canonical_pubkey,
        grants=[
            KeyGrantOut.from_persisted(row, ledger_hash) for row, ledger_hash in zip(rows, ledger_hashes, strict=True)
        ],
    )
