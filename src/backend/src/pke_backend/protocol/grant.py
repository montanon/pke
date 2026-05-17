"""Key grant protocol payload — mirror of `shared/schemas/key_grant.json`."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict

from .types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime

__all__ = ["KeyGrant"]


class KeyGrant(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    type: Literal["key_grant"]
    version: str
    grant_id: str
    snapshot_id: str
    recipient_encryption_public_key: Base64UrlBytes
    wrapped_snapshot_key: Base64UrlBytes
    wrapping_algorithm: str
    granted_by_signing_public_key: Base64UrlBytes
    grant_timestamp: UTCDatetime
    grant_signature: Base64UrlBytes
