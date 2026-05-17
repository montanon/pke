"""``POST /reports`` endpoint (HLAM-79).

Accepts a signed :class:`ReportAction`, verifies the signature, persists a
:class:`pke_backend.models.Report` row, and appends a ``REPORTED`` ledger
entry — all in one transaction.

Errors flow through the global handlers in :mod:`pke_backend.api.errors`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.encoding import b64url_encode
from pke_backend.db import get_session
from pke_backend.protocol.report_action import ReportAction
from pke_backend.schemas.reports import ReportCreatedResponse
from pke_backend.security.dependencies import require_user
from pke_backend.services.reports import create_report

__all__ = ["router"]

router = APIRouter(prefix="/reports", tags=["reports"], dependencies=[Depends(require_user)])


@router.post("", status_code=201, response_model=ReportCreatedResponse)
async def post_report(
    action: ReportAction,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ReportCreatedResponse:
    report, entry = await create_report(session, action)
    return ReportCreatedResponse(
        report_id=report.report_id,
        ledger_entry_id=entry.ledger_entry_id,
        ledger_entry_hash=b64url_encode(entry.entry_hash),
    )
