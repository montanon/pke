"""``POST /freezes`` endpoint (HLAM-79)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.encoding import b64url_encode
from pke_backend.db import get_session
from pke_backend.protocol.freeze import FreezeAction
from pke_backend.schemas.freezes import FreezeCreatedResponse
from pke_backend.services.freezes import create_freeze

__all__ = ["router"]

router = APIRouter(prefix="/freezes", tags=["freezes"])


@router.post("", status_code=201, response_model=FreezeCreatedResponse)
async def post_freeze(
    action: FreezeAction,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FreezeCreatedResponse:
    freeze, entry = await create_freeze(session, action)
    return FreezeCreatedResponse(
        freeze_id=freeze.freeze_id,
        ledger_entry_id=entry.ledger_entry_id,
        ledger_entry_hash=b64url_encode(entry.entry_hash),
    )
