"""HTTP response shape for ``POST /reports`` (HLAM-79).

Per AC #1: ``201`` with ``{report_id, ledger_entry_id, ledger_entry_hash}``.
``ledger_entry_hash`` is base64url-no-pad of the 32-byte SHA-256 digest
(matches the wire encoding used in :class:`pke_backend.protocol.ledger.LedgerEntry`).
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict

__all__ = ["ReportCreatedResponse"]


class ReportCreatedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: uuid.UUID
    ledger_entry_id: uuid.UUID
    ledger_entry_hash: str
