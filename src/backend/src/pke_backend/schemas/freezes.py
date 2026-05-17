"""HTTP request / response shapes for ``/freezes`` (HLAM-79 + HLAM-82).

* ``FreezeCreatedResponse`` — POST /freezes envelope (HLAM-79).
* ``FreezeOut`` / ``FreezesListResponse`` — GET /snapshots/{id}/freezes
  envelope (HLAM-82 AC #9). ``ledger_entry_hash`` is hex-encoded; the
  envelope wraps the at-most-one freeze row so the response shape stays
  list-shaped for future-proofing.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, field_serializer

from pke_backend.crypto.encoding import hex_encode

if TYPE_CHECKING:
    from pke_backend.models.freeze import Freeze as _FreezeORM

__all__ = [
    "FreezeCreatedResponse",
    "FreezeOut",
    "FreezesListResponse",
]


class FreezeCreatedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    freeze_id: uuid.UUID
    ledger_entry_id: uuid.UUID
    ledger_entry_hash: str


class FreezeOut(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    freeze_id: uuid.UUID
    snapshot_id: uuid.UUID
    triggered_by_report_id: uuid.UUID
    freeze_status: str
    created_at: datetime
    freeze_signature: str
    ledger_entry_hash: str

    @field_serializer("created_at")
    def _serialize_utc_z(self, value: datetime) -> str:
        iso = value.isoformat()
        if iso.endswith("+00:00"):
            return iso[: -len("+00:00")] + "Z"
        return iso

    @classmethod
    def from_persisted(
        cls,
        freeze: _FreezeORM,
        *,
        ledger_entry_hash: bytes,
    ) -> FreezeOut:
        return cls(
            freeze_id=freeze.freeze_id,
            snapshot_id=freeze.snapshot_id,
            triggered_by_report_id=freeze.triggered_by_report_id,
            freeze_status=freeze.freeze_status,
            created_at=freeze.created_at,
            freeze_signature=hex_encode(freeze.freeze_signature),
            ledger_entry_hash=hex_encode(ledger_entry_hash),
        )


class FreezesListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    freezes: list[FreezeOut]
