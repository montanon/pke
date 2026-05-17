"""Verification report protocol payload — mirror of `shared/schemas/verification_report.json`."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field

from .types import ToJsonValueMixin

__all__ = [
    "AttestationStrength",
    "AttestationSummary",
    "VerificationReport",
    "VerificationResults",
]


class AttestationStrength(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationResults(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    ciphertext_hash_verified: bool
    owner_signature_verified: bool
    witness_signatures_verified: bool
    ledger_hash_chain_verified: bool
    recipient_key_grant_verified: bool


class AttestationSummary(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    witness_count: int = Field(ge=0)
    transport: str | None = None
    attestation_strength: AttestationStrength | None = None


class VerificationReport(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    type: Literal["verification_report"]
    version: str
    snapshot_id: str
    results: VerificationResults
    limitations: list[str]
    attestation_summary: AttestationSummary | None = None
