"""Pydantic wire-shape tests for ``protocol.freeze.FreezeAction`` (HLAM-79).

Pins the same kind of contracts as :mod:`tests.protocol.test_report_action_model`
but for the freeze payload. See ``shared/schemas/freeze.json``.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from pydantic import ValidationError

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import EncodingError
from pke_backend.protocol.freeze import FREEZE_VERSION, FreezeAction


def _valid_payload() -> dict[str, Any]:
    return {
        "type": "freeze",
        "version": FREEZE_VERSION,
        "freeze_id": "00000000-0000-0000-0000-000000000010",
        "snapshot_id": "00000000-0000-0000-0000-000000000020",
        "triggered_by": "00000000-0000-0000-0000-000000000001",
        "frozen_by_signing_public_key": b64url_encode(b"\x04" + b"\x20" * 64),
        "freeze_timestamp": "2026-05-15T00:02:05Z",
        "freeze_signature": b64url_encode(b"\x30" * 64),
    }


def test_parse_canonical_payload() -> None:
    action = FreezeAction.model_validate(_valid_payload())
    assert action.type == "freeze"
    assert action.version == "0.1"
    assert action.triggered_by == "00000000-0000-0000-0000-000000000001"
    assert action.frozen_by_signing_public_key == b"\x04" + b"\x20" * 64
    assert action.freeze_signature == b"\x30" * 64


def test_rejects_unknown_top_level_key() -> None:
    payload = _valid_payload() | {"extra": "x"}
    with pytest.raises(ValidationError):
        FreezeAction.model_validate(payload)


def test_rejects_wrong_type_discriminator() -> None:
    payload = _valid_payload() | {"type": "report"}
    with pytest.raises(ValidationError):
        FreezeAction.model_validate(payload)


@pytest.mark.parametrize(
    "missing_field",
    [
        "type",
        "version",
        "freeze_id",
        "snapshot_id",
        "triggered_by",
        "frozen_by_signing_public_key",
        "freeze_timestamp",
        "freeze_signature",
    ],
)
def test_rejects_missing_required_field(missing_field: str) -> None:
    payload = _valid_payload()
    del payload[missing_field]
    with pytest.raises(ValidationError):
        FreezeAction.model_validate(payload)


def test_rejects_padded_base64_pubkey() -> None:
    raw = b"\x04" + b"\x20" * 64
    padded = base64.urlsafe_b64encode(raw).decode("ascii")
    payload = _valid_payload() | {"frozen_by_signing_public_key": padded}
    # See `test_report_action_model::test_rejects_padded_base64_pubkey` —
    # ``EncodingError`` may propagate raw since it's not a ``ValueError``.
    with pytest.raises((ValidationError, EncodingError)):
        FreezeAction.model_validate(payload)


def test_rejects_timestamp_without_z_suffix() -> None:
    payload = _valid_payload() | {"freeze_timestamp": "2026-05-15T00:02:05+00:00"}
    with pytest.raises(ValidationError):
        FreezeAction.model_validate(payload)


def test_to_json_value_round_trips_through_canonicalize() -> None:
    action = FreezeAction.model_validate(_valid_payload())
    body = action.to_json_value()
    once = canonicalize(body)
    twice = canonicalize(body)
    assert once == twice
    assert b'"type":"freeze"' in once


def test_to_json_value_emits_base64url_for_binary_fields() -> None:
    action = FreezeAction.model_validate(_valid_payload())
    body = action.to_json_value()
    assert isinstance(body, dict)
    assert isinstance(body["frozen_by_signing_public_key"], str)
    assert "=" not in body["frozen_by_signing_public_key"]
    assert isinstance(body["freeze_signature"], str)
    assert "=" not in body["freeze_signature"]


def test_to_json_value_emits_z_suffixed_timestamp() -> None:
    action = FreezeAction.model_validate(_valid_payload())
    body = action.to_json_value()
    assert isinstance(body, dict)
    assert body["freeze_timestamp"] == "2026-05-15T00:02:05Z"
