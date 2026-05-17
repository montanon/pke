"""HTTP response shape for ``POST /freezes`` (HLAM-79).

Mirrors :class:`pke_backend.schemas.reports.ReportCreatedResponse` —
``ledger_entry_hash`` is base64url-no-pad of the 32-byte SHA-256 digest.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict

__all__ = ["FreezeCreatedResponse"]


class FreezeCreatedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    freeze_id: uuid.UUID
    ledger_entry_id: uuid.UUID
    ledger_entry_hash: str
