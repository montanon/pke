"""HTTP request/response models for the `/key-grants` endpoint.

`KeyGrantIn` is the inbound request model. It mirrors the wire shape of
``src/shared/schemas/key_grant.json`` and the protocol-level mirror in
``pke_backend.protocol.grant``, but adds the API-boundary validators that
``protocol.KeyGrant`` deliberately omits — the wrapping-algorithm allowlist,
the decoded-length checks for binary fields, the UUID format check for
``grant_id``, and the ``version`` literal pin.

`canonical_body_bytes()` returns the exact bytes the owner device signed
under HLAM-3 §Signed-body rule. The grant endpoint (HLAM-40 Story #3) feeds
those bytes into the ECDSA verifier; any drift between this output and the
device-side signed body would silently invalidate every grant.

`KeyGrantOut` is the response model. ``from_persisted`` constructs it from
the persisted ORM row (``pke_backend.models.key_grant.KeyGrant``) plus the
hash of the ``KEY_GRANTED`` ledger entry written by F1 — hex-encoded for
the response. ``grant_timestamp`` and ``created_at`` carry ``datetime``
values in-memory and serialise to ``Z``-suffixed ISO-8601 via
``UTCDatetime`` so ``model_dump(mode="json")`` round-trips through
``model_validate`` cleanly.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Final, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, field_validator

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode, hex_encode
from pke_backend.crypto.types import JsonValue
from pke_backend.protocol.types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime

__all__ = [
    "ECDSA_P1363_SIGNATURE_BYTES",
    "KEY_GRANT_VERSION",
    "RECIPIENT_PUBLIC_KEY_BYTES",
    "SIGNING_PUBLIC_KEY_BYTES",
    "WRAPPED_SNAPSHOT_KEY_BYTES",
    "WRAPPING_ALGORITHM_ALLOWLIST",
    "KeyGrantIn",
    "KeyGrantListResponse",
    "KeyGrantOut",
    "PersistedKeyGrant",
]

# Locked v0.1 wrapping construction per HLAM-3 §Versioning. Future protocol
# revisions mint a new identifier (e.g. "ecdhp256+aesgcm256-v2"); never mutate
# either of these.
KEY_GRANT_VERSION: Final[str] = "0.1"
WRAPPING_ALGORITHM_ALLOWLIST: Final[frozenset[str]] = frozenset({"ecdhp256+aesgcm256"})

# 12-byte nonce || 32-byte AES-256 ciphertext || 16-byte GCM tag per HLAM-3 §AES-256-GCM.
WRAPPED_SNAPSHOT_KEY_BYTES: Final[int] = 60

# Uncompressed P-256 point: 0x04 || X(32) || Y(32) per HLAM-3 §Binary field encoding.
RECIPIENT_PUBLIC_KEY_BYTES: Final[int] = 65
SIGNING_PUBLIC_KEY_BYTES: Final[int] = 65

# Raw P1363 ECDSA signature: r(32) || s(32) per HLAM-3 §ECDSA.
ECDSA_P1363_SIGNATURE_BYTES: Final[int] = 64


class KeyGrantIn(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")

    type: Literal["key_grant"]
    version: Literal["0.1"]
    grant_id: str
    snapshot_id: str
    recipient_encryption_public_key: Base64UrlBytes
    wrapped_snapshot_key: Base64UrlBytes
    wrapping_algorithm: str
    granted_by_signing_public_key: Base64UrlBytes
    grant_timestamp: UTCDatetime
    grant_signature: Base64UrlBytes

    @field_validator("grant_id")
    @classmethod
    def _validate_grant_id(cls, value: str) -> str:
        # uuid.UUID rejects empty strings and any non-UUID input with ValueError;
        # Pydantic wraps that into ValidationError automatically.
        uuid.UUID(value)
        return value

    @field_validator("wrapping_algorithm")
    @classmethod
    def _validate_wrapping_algorithm(cls, value: str) -> str:
        if value not in WRAPPING_ALGORITHM_ALLOWLIST:
            allowed = sorted(WRAPPING_ALGORITHM_ALLOWLIST)
            raise ValueError(f"wrapping_algorithm not in v0.1 allowlist; allowed={allowed}")
        return value

    @field_validator("recipient_encryption_public_key")
    @classmethod
    def _validate_recipient_encryption_public_key(cls, value: bytes) -> bytes:
        if len(value) != RECIPIENT_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"recipient_encryption_public_key must be {RECIPIENT_PUBLIC_KEY_BYTES} bytes "
                f"(uncompressed P-256), got {len(value)}"
            )
        return value

    @field_validator("granted_by_signing_public_key")
    @classmethod
    def _validate_granted_by_signing_public_key(cls, value: bytes) -> bytes:
        if len(value) != SIGNING_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"granted_by_signing_public_key must be {SIGNING_PUBLIC_KEY_BYTES} bytes "
                f"(uncompressed P-256), got {len(value)}"
            )
        return value

    @field_validator("wrapped_snapshot_key")
    @classmethod
    def _validate_wrapped_snapshot_key(cls, value: bytes) -> bytes:
        if len(value) != WRAPPED_SNAPSHOT_KEY_BYTES:
            raise ValueError(
                f"wrapped_snapshot_key must be {WRAPPED_SNAPSHOT_KEY_BYTES} bytes "
                f"(12 nonce + 32 ciphertext + 16 tag), got {len(value)}"
            )
        return value

    @field_validator("grant_signature")
    @classmethod
    def _validate_grant_signature(cls, value: bytes) -> bytes:
        if len(value) != ECDSA_P1363_SIGNATURE_BYTES:
            raise ValueError(
                f"grant_signature must be {ECDSA_P1363_SIGNATURE_BYTES} bytes (raw P1363), got {len(value)}"
            )
        return value

    def dump_exclude_signature(self) -> JsonValue:
        dumped = self.model_dump(mode="json", by_alias=False, exclude={"grant_signature"})
        return cast("JsonValue", dumped)

    def canonical_body_bytes(self) -> bytes:
        return canonicalize(self.dump_exclude_signature())


class PersistedKeyGrant(Protocol):
    """Structural type for a persisted KeyGrant row.

    Matches ``pke_backend.models.key_grant.KeyGrant`` (HLAM-72) — public keys
    are stored as base64url-no-pad strings (Text columns); wrapped key and
    signature are raw bytes (LargeBinary columns).
    """

    grant_id: uuid.UUID
    snapshot_id: uuid.UUID
    recipient_encryption_public_key: str
    wrapped_snapshot_key: bytes
    wrapping_algorithm: str
    granted_by_signing_public_key: str
    grant_timestamp: datetime
    grant_signature: bytes
    version: str
    created_at: datetime


class KeyGrantOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["key_grant"] = "key_grant"
    version: Literal["0.1"]
    grant_id: uuid.UUID
    snapshot_id: uuid.UUID
    recipient_encryption_public_key: str
    wrapped_snapshot_key: str
    wrapping_algorithm: str
    granted_by_signing_public_key: str
    grant_timestamp: UTCDatetime
    grant_signature: str
    created_at: UTCDatetime
    ledger_entry_hash: str

    @classmethod
    def from_persisted(
        cls,
        orm_row: PersistedKeyGrant,
        ledger_entry_hash: bytes,
    ) -> KeyGrantOut:
        return cls(
            version=cast("Literal['0.1']", orm_row.version),
            grant_id=orm_row.grant_id,
            snapshot_id=orm_row.snapshot_id,
            recipient_encryption_public_key=orm_row.recipient_encryption_public_key,
            wrapped_snapshot_key=b64url_encode(orm_row.wrapped_snapshot_key),
            wrapping_algorithm=orm_row.wrapping_algorithm,
            granted_by_signing_public_key=orm_row.granted_by_signing_public_key,
            grant_timestamp=orm_row.grant_timestamp,
            grant_signature=b64url_encode(orm_row.grant_signature),
            created_at=orm_row.created_at,
            ledger_entry_hash=hex_encode(ledger_entry_hash),
        )


class KeyGrantListResponse(BaseModel):
    """GET /key-grants?recipient_encryption_public_key=... envelope (HLAM-75).

    ``recipient_encryption_public_key`` echoes the (validated, base64url)
    query parameter back to the client so a downstream auditor can correlate
    the request to the response without re-parsing the URL.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    recipient_encryption_public_key: str
    grants: list[KeyGrantOut]
