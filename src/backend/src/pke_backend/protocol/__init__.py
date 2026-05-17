"""Protocol payload models — Pydantic v2 mirrors of the 5 shared JSON Schemas.

Distinct from `pke_backend.schemas` (HTTP request/response models). All models
share the canonical-bytes path via `to_json_value()`.
"""

from __future__ import annotations

from .attestation import ProximityClaim, WitnessAttestation
from .freeze import FREEZE_VERSION, FreezeAction
from .grant import KeyGrant
from .ledger import LedgerEntry, LedgerEventType
from .report import (
    AttestationStrength,
    AttestationSummary,
    VerificationReport,
    VerificationResults,
)
from .report_action import REPORT_VERSION, ReasonCategory, ReportAction
from .snapshot import MetadataPolicy, SnapshotCommitment
from .types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime

__all__ = [
    "FREEZE_VERSION",
    "REPORT_VERSION",
    "AttestationStrength",
    "AttestationSummary",
    "Base64UrlBytes",
    "FreezeAction",
    "KeyGrant",
    "LedgerEntry",
    "LedgerEventType",
    "MetadataPolicy",
    "ProximityClaim",
    "ReasonCategory",
    "ReportAction",
    "SnapshotCommitment",
    "ToJsonValueMixin",
    "UTCDatetime",
    "VerificationReport",
    "VerificationResults",
    "WitnessAttestation",
]
