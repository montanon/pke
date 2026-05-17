"""Pydantic wire-shape tests for ``protocol.report_action.ReportAction`` (HLAM-79).

The on-the-wire schema is fixed by ``shared/schemas/report.json`` and the
canonical-encoding spec (``context/16_canonical_encoding.md``):

* ``type`` is the literal ``"report"``,
* unknown top-level keys are rejected (``additionalProperties: false`` ↔
  ``extra="forbid"``),
* ``reason_category`` is one of four locked values,
* binary fields are unpadded base64url (``Base64UrlBytes``),
* ``report_timestamp`` is UTC with a trailing ``Z`` (``UTCDatetime``).

These tests pin every rejection branch so the API layer can rely on Pydantic
to filter malformed bodies before any signature work runs.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from pydantic import ValidationError

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import EncodingError
from pke_backend.protocol.report_action import REPORT_VERSION, ReasonCategory, ReportAction


def _valid_payload() -> dict[str, Any]:
    return {
        "type": "report",
        "version": REPORT_VERSION,
        "report_id": "00000000-0000-0000-0000-000000000001",
        "snapshot_id": "00000000-0000-0000-0000-000000000002",
        "reason_category": "abuse_concern",
        "reported_by_signing_public_key": b64url_encode(b"\x04" + b"\x10" * 64),
        "report_timestamp": "2026-05-15T00:02:00Z",
        "report_signature": b64url_encode(b"\x20" * 64),
    }


def test_parse_canonical_payload() -> None:
    action = ReportAction.model_validate(_valid_payload())
    assert action.type == "report"
    assert action.version == "0.1"
    assert action.reason_category is ReasonCategory.ABUSE_CONCERN
    assert action.reported_by_signing_public_key == b"\x04" + b"\x10" * 64
    assert action.report_signature == b"\x20" * 64
    assert action.report_timestamp.isoformat().endswith("+00:00")


def test_rejects_unknown_top_level_key() -> None:
    payload = _valid_payload() | {"extra": "x"}
    with pytest.raises(ValidationError):
        ReportAction.model_validate(payload)


def test_rejects_wrong_type_discriminator() -> None:
    payload = _valid_payload() | {"type": "freeze"}
    with pytest.raises(ValidationError):
        ReportAction.model_validate(payload)


def test_rejects_unknown_reason_category() -> None:
    payload = _valid_payload() | {"reason_category": "bogus_reason"}
    with pytest.raises(ValidationError):
        ReportAction.model_validate(payload)


@pytest.mark.parametrize(
    "missing_field",
    [
        "type",
        "version",
        "report_id",
        "snapshot_id",
        "reason_category",
        "reported_by_signing_public_key",
        "report_timestamp",
        "report_signature",
    ],
)
def test_rejects_missing_required_field(missing_field: str) -> None:
    payload = _valid_payload()
    del payload[missing_field]
    with pytest.raises(ValidationError):
        ReportAction.model_validate(payload)


def test_rejects_padded_base64_pubkey() -> None:
    raw = b"\x04" + b"\x10" * 64
    padded = base64.urlsafe_b64encode(raw).decode("ascii")  # ends with "="
    payload = _valid_payload() | {"reported_by_signing_public_key": padded}
    # ``Base64UrlBytes`` decodes through the strict crypto helper; the helper's
    # ``EncodingError`` is not a ``ValueError``, so Pydantic does not wrap it.
    # Either surface is acceptable as long as the payload is rejected before
    # any signature work runs.
    with pytest.raises((ValidationError, EncodingError)):
        ReportAction.model_validate(payload)


def test_rejects_timestamp_without_z_suffix() -> None:
    payload = _valid_payload() | {"report_timestamp": "2026-05-15T00:02:00+00:00"}
    with pytest.raises(ValidationError):
        ReportAction.model_validate(payload)


def test_rejects_timestamp_naive() -> None:
    payload = _valid_payload() | {"report_timestamp": "2026-05-15T00:02:00"}
    with pytest.raises(ValidationError):
        ReportAction.model_validate(payload)


def test_to_json_value_round_trips_through_canonicalize() -> None:
    action = ReportAction.model_validate(_valid_payload())
    body = action.to_json_value()
    once = canonicalize(body)
    twice = canonicalize(body)
    assert once == twice
    assert b'"type":"report"' in once
    assert b'"reason_category":"abuse_concern"' in once


def test_to_json_value_emits_base64url_for_binary_fields() -> None:
    action = ReportAction.model_validate(_valid_payload())
    body = action.to_json_value()
    assert isinstance(body, dict)
    assert isinstance(body["reported_by_signing_public_key"], str)
    assert "=" not in body["reported_by_signing_public_key"]
    assert isinstance(body["report_signature"], str)
    assert "=" not in body["report_signature"]


def test_to_json_value_emits_z_suffixed_timestamp() -> None:
    action = ReportAction.model_validate(_valid_payload())
    body = action.to_json_value()
    assert isinstance(body, dict)
    assert body["report_timestamp"] == "2026-05-15T00:02:00Z"
