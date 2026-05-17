from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ConfigDict, ValidationError

from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import EncodingError
from pke_backend.protocol.types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime


class _Sample(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    blob: Base64UrlBytes
    ts: UTCDatetime


# ---------------------------------------------------------------------------
# Base64UrlBytes
# ---------------------------------------------------------------------------


def test_base64url_bytes_round_trip() -> None:
    raw = b"\x00\x01\x02\xfe\xff"
    encoded = b64url_encode(raw)
    model = _Sample.model_validate({"blob": encoded, "ts": "2026-05-15T00:00:00Z"})
    assert model.blob == raw
    dumped = model.model_dump(mode="json")
    assert dumped["blob"] == encoded


def test_base64url_bytes_accepts_raw_bytes() -> None:
    model = _Sample.model_validate({"blob": b"\x01\x02", "ts": "2026-05-15T00:00:00Z"})
    assert model.blob == b"\x01\x02"


@pytest.mark.parametrize(
    "bad",
    [
        "AAA=",  # padding
        "AA==",  # padding
        "ab+d",  # standard alphabet
        "ab/d",  # standard alphabet
        "A",  # length 1 (mod 4 == 1)
        "AAAAA",  # length 5 (mod 4 == 1)
    ],
)
def test_base64url_bytes_rejects_invalid_strings(bad: str) -> None:
    with pytest.raises((ValidationError, EncodingError)):
        _Sample.model_validate({"blob": bad, "ts": "2026-05-15T00:00:00Z"})


def test_base64url_bytes_rejects_non_ascii() -> None:
    with pytest.raises((ValidationError, EncodingError)):
        _Sample.model_validate({"blob": "café", "ts": "2026-05-15T00:00:00Z"})


def test_base64url_bytes_rejects_wrong_type() -> None:
    with pytest.raises(ValidationError):
        _Sample.model_validate({"blob": 123, "ts": "2026-05-15T00:00:00Z"})


# ---------------------------------------------------------------------------
# UTCDatetime
# ---------------------------------------------------------------------------


def test_utc_datetime_accepts_z_suffix() -> None:
    model = _Sample.model_validate({"blob": "AA", "ts": "2026-05-15T00:00:00Z"})
    assert model.ts == datetime(2026, 5, 15, 0, 0, 0, tzinfo=UTC)


def test_utc_datetime_accepts_utc_datetime() -> None:
    dt = datetime(2026, 5, 15, tzinfo=UTC)
    model = _Sample.model_validate({"blob": "AA", "ts": dt})
    assert model.ts == dt


@pytest.mark.parametrize(
    "bad",
    [
        "2026-05-15T00:00:00",  # no Z
        "2026-05-15T00:00:00+02:00",  # offset, no Z
        "2026-05-15T00:00:00+00:00",  # offset form, no Z
        "2026-05-15",  # date-only
    ],
)
def test_utc_datetime_rejects_invalid_strings(bad: str) -> None:
    with pytest.raises(ValidationError):
        _Sample.model_validate({"blob": "AA", "ts": bad})


def test_utc_datetime_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError):
        _Sample.model_validate({"blob": "AA", "ts": datetime(2026, 5, 15)})  # noqa: DTZ001


def test_utc_datetime_rejects_non_utc_tz() -> None:
    plus_two = timezone(timedelta(hours=2))
    with pytest.raises(ValidationError):
        _Sample.model_validate({"blob": "AA", "ts": datetime(2026, 5, 15, tzinfo=plus_two)})


def test_utc_datetime_rejects_wrong_type() -> None:
    with pytest.raises(ValidationError):
        _Sample.model_validate({"blob": "AA", "ts": 12345})


def test_utc_datetime_serializes_with_z() -> None:
    model = _Sample.model_validate({"blob": "AA", "ts": "2026-05-15T00:00:00Z"})
    dumped = model.model_dump(mode="json")
    assert dumped["ts"] == "2026-05-15T00:00:00Z"
    assert not dumped["ts"].endswith("+00:00")


# ---------------------------------------------------------------------------
# ToJsonValueMixin
# ---------------------------------------------------------------------------


def test_to_json_value_returns_dict_with_strings() -> None:
    model = _Sample.model_validate({"blob": "AAA", "ts": "2026-05-15T00:00:00Z"})
    out = model.to_json_value()
    assert isinstance(out, dict)
    assert isinstance(out["blob"], str)
    assert isinstance(out["ts"], str)
    assert out["ts"].endswith("Z")
