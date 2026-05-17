"""Snapshot commitment protocol payload — mirror of `shared/schemas/snapshot_commitment.json`."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict

from .types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime

__all__ = ["MetadataPolicy", "SnapshotCommitment"]


class MetadataPolicy(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    location_public: bool
    media_type: str
    location_precision: str | None = None


class SnapshotCommitment(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    type: Literal["snapshot_commitment"]
    version: str
    snapshot_id: str
    ciphertext_hash: Base64UrlBytes
    owner_signing_public_key: Base64UrlBytes
    owner_encryption_public_key: Base64UrlBytes
    capture_timestamp: UTCDatetime
    metadata_policy: MetadataPolicy
    session_nonce: Base64UrlBytes
    owner_signature: Base64UrlBytes
