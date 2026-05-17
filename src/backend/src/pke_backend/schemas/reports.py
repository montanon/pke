"""HTTP request / response shapes for ``/reports`` (HLAM-79 + HLAM-82).

* ``ReportCreatedResponse`` — POST /reports envelope (HLAM-79).
* ``ReportOut`` / ``ReportsListResponse`` — GET /snapshots/{id}/reports
  envelope (HLAM-82 AC #8). ``ledger_entry_hash`` is hex-encoded on read
  endpoints (consistent with :class:`pke_backend.schemas.snapshot.SnapshotOut`);
  the POST envelope keeps base64url for backwards compatibility.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, field_serializer

from pke_backend.crypto.encoding import hex_encode

if TYPE_CHECKING:
    from pke_backend.models.report import Report as _ReportORM

__all__ = [
    "ReportCreatedResponse",
    "ReportOut",
    "ReportsListResponse",
]


class ReportCreatedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: uuid.UUID
    ledger_entry_id: uuid.UUID
    ledger_entry_hash: str


class ReportOut(BaseModel):
    """Single report row for the list-reports GET endpoint.

    Hex-encoded binary fields, Z-suffixed timestamps — mirrors the surface
    of :class:`pke_backend.schemas.snapshot.SnapshotOut` so downstream
    auditors get a uniform on-the-wire encoding for inspectable hashes.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: uuid.UUID
    snapshot_id: uuid.UUID
    reason_category: str
    reported_by_signing_public_key: str
    report_status: str
    created_at: datetime
    report_signature: str
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
        report: _ReportORM,
        *,
        ledger_entry_hash: bytes,
    ) -> ReportOut:
        return cls(
            report_id=report.report_id,
            snapshot_id=report.snapshot_id,
            reason_category=report.reason_category.value,
            reported_by_signing_public_key=hex_encode(report.reported_by_signing_public_key),
            report_status=report.report_status,
            created_at=report.created_at,
            report_signature=hex_encode(report.report_signature),
            ledger_entry_hash=hex_encode(ledger_entry_hash),
        )


class ReportsListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    reports: list[ReportOut]
