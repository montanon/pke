"""Witness attestation protocol payload — mirror of `shared/schemas/witness_attestation.json`."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict

from .types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime

__all__ = ["ProximityClaim", "WitnessAttestation"]


class ProximityClaim(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    method: str
    exact_location_public: bool


class WitnessAttestation(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    type: Literal["witness_attestation"]
    version: str
    snapshot_id: str
    ciphertext_hash: Base64UrlBytes
    session_nonce: Base64UrlBytes
    owner_signing_public_key: Base64UrlBytes
    witness_signing_public_key: Base64UrlBytes
    witness_timestamp: UTCDatetime
    transport: str
    proximity_claim: ProximityClaim
    witness_signature: Base64UrlBytes
