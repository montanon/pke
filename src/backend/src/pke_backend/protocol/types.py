"""Reusable Pydantic field types and a JSON-serialisation mixin for protocol models.

`Base64UrlBytes` stores raw bytes in-memory and (de)serialises to unpadded base64url
through the strict crypto decoder. `UTCDatetime` enforces a `Z`-suffixed ISO-8601
form on the wire and `tzinfo == timezone.utc` for in-memory `datetime` inputs.
`ToJsonValueMixin` is a thin BaseModel subclass that exposes `to_json_value()`,
returning a `JsonValue` ready for `pke_backend.crypto.canonicalize`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, cast

from pydantic import BaseModel, BeforeValidator, PlainSerializer

from pke_backend.crypto.encoding import b64url_decode, b64url_encode
from pke_backend.crypto.types import JsonValue

__all__ = ["Base64UrlBytes", "ToJsonValueMixin", "UTCDatetime"]


def _decode_b64url(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return b64url_decode(value)
    # Raise ValueError (not TypeError) so Pydantic wraps into ValidationError.
    raise ValueError(f"expected str or bytes, got {type(value).__name__}")


Base64UrlBytes = Annotated[
    bytes,
    BeforeValidator(_decode_b64url),
    PlainSerializer(b64url_encode, return_type=str, when_used="always"),
]


def _parse_utc_z(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is not UTC:
            raise ValueError("datetime must be UTC")
        return value
    if isinstance(value, str):
        if not value.endswith("Z"):
            raise ValueError("datetime string must end with 'Z'")
        stripped = value[:-1]
        # Disallow nested offset specifiers like "+00:00Z".
        if "+" in stripped or stripped.count("-") > 2:
            raise ValueError("datetime string must not contain an offset")
        parsed = datetime.fromisoformat(stripped)
        if parsed.tzinfo is not None:
            raise ValueError("datetime string must be naive before the trailing 'Z'")
        return parsed.replace(tzinfo=UTC)
    # Raise ValueError (not TypeError) so Pydantic wraps into ValidationError.
    raise ValueError(f"expected datetime or str, got {type(value).__name__}")


def _serialize_utc_z(value: datetime) -> str:
    iso = value.isoformat()
    if iso.endswith("+00:00"):
        return iso[: -len("+00:00")] + "Z"
    return iso


UTCDatetime = Annotated[
    datetime,
    BeforeValidator(_parse_utc_z),
    PlainSerializer(_serialize_utc_z, return_type=str, when_used="always"),
]


class ToJsonValueMixin(BaseModel):
    def to_json_value(self) -> JsonValue:
        return cast("JsonValue", self.model_dump(mode="json", by_alias=False))
