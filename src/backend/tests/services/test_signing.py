"""Unit tests for ``services.signing`` (HLAM-79).

Exercises the round trip protocol-Pydantic-model → canonical-body → sign →
verify against the strict crypto primitives. These are the boundary tests:
if anything here regresses, every downstream signed-payload endpoint breaks.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import SignatureFormatError, SignatureVerificationError
from pke_backend.crypto.primitives.sign import sign as p256_sign
from pke_backend.protocol.freeze import FREEZE_VERSION, FreezeAction
from pke_backend.protocol.report_action import REPORT_VERSION, ReportAction
from pke_backend.services.signing import (
    canonical_signed_body,
    load_p256_public_key,
    verify_action_signature,
)


def _uncompressed_pubkey_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def _signed_report_action(private_key: ec.EllipticCurvePrivateKey) -> ReportAction:
    pubkey = _uncompressed_pubkey_bytes(private_key)
    base: dict[str, Any] = {
        "type": "report",
        "version": REPORT_VERSION,
        "report_id": "11111111-1111-1111-1111-111111111111",
        "snapshot_id": "22222222-2222-2222-2222-222222222222",
        "reason_category": "abuse_concern",
        "reported_by_signing_public_key": b64url_encode(pubkey),
        "report_timestamp": "2026-05-15T00:02:00Z",
        "report_signature": b64url_encode(b"\x00" * 64),
    }
    action = ReportAction.model_validate(base)
    body = canonical_signed_body(action, "report_signature")
    sig = p256_sign(body, private_key)
    base["report_signature"] = b64url_encode(sig)
    return ReportAction.model_validate(base)


def _signed_freeze_action(private_key: ec.EllipticCurvePrivateKey) -> FreezeAction:
    pubkey = _uncompressed_pubkey_bytes(private_key)
    base: dict[str, Any] = {
        "type": "freeze",
        "version": FREEZE_VERSION,
        "freeze_id": "33333333-3333-3333-3333-333333333333",
        "snapshot_id": "22222222-2222-2222-2222-222222222222",
        "triggered_by": "11111111-1111-1111-1111-111111111111",
        "frozen_by_signing_public_key": b64url_encode(pubkey),
        "freeze_timestamp": "2026-05-15T00:02:05Z",
        "freeze_signature": b64url_encode(b"\x00" * 64),
    }
    action = FreezeAction.model_validate(base)
    body = canonical_signed_body(action, "freeze_signature")
    sig = p256_sign(body, private_key)
    base["freeze_signature"] = b64url_encode(sig)
    return FreezeAction.model_validate(base)


# --- canonical_signed_body ------------------------------------------------


def test_canonical_signed_body_drops_named_field() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    action = _signed_report_action(private_key)
    body = canonical_signed_body(action, "report_signature")
    # The dropped field must not appear anywhere in the canonical bytes.
    assert b"report_signature" not in body
    # Every other field must remain.
    for field in [
        b"type",
        b"version",
        b"report_id",
        b"snapshot_id",
        b"reason_category",
        b"reported_by_signing_public_key",
        b"report_timestamp",
    ]:
        assert field in body


def test_canonical_signed_body_is_byte_deterministic() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    action = _signed_report_action(private_key)
    once = canonical_signed_body(action, "report_signature")
    twice = canonical_signed_body(action, "report_signature")
    assert once == twice


def test_canonical_signed_body_matches_manual_canonicalize_minus_field() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    action = _signed_report_action(private_key)
    expected_body = action.to_json_value()
    assert isinstance(expected_body, dict)
    expected_body.pop("report_signature", None)
    expected = canonicalize(expected_body)
    assert canonical_signed_body(action, "report_signature") == expected


def test_canonical_signed_body_drops_freeze_signature_for_freeze() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    action = _signed_freeze_action(private_key)
    body = canonical_signed_body(action, "freeze_signature")
    assert b"freeze_signature" not in body
    assert b"frozen_by_signing_public_key" in body


# --- load_p256_public_key -------------------------------------------------


def test_load_p256_public_key_round_trips_valid_uncompressed_point() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    raw = _uncompressed_pubkey_bytes(private_key)
    loaded = load_p256_public_key(raw)
    assert isinstance(loaded, ec.EllipticCurvePublicKey)
    assert isinstance(loaded.curve, ec.SECP256R1)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x04" * 32,
        b"\x04" * 64,
        b"\x05" + b"\x00" * 64,  # wrong leading byte
        b"\x00" * 128,
    ],
)
def test_load_p256_public_key_rejects_invalid_inputs(raw: bytes) -> None:
    with pytest.raises(SignatureFormatError):
        load_p256_public_key(raw)


def test_load_p256_public_key_rejects_non_bytes() -> None:
    with pytest.raises(SignatureFormatError):
        load_p256_public_key("not bytes")  # type: ignore[arg-type]


# --- verify_action_signature ----------------------------------------------


def test_verify_action_signature_accepts_correctly_signed_report() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    action = _signed_report_action(private_key)
    verify_action_signature(
        action,
        signature_field="report_signature",
        public_key_field="reported_by_signing_public_key",
    )


def test_verify_action_signature_accepts_correctly_signed_freeze() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    action = _signed_freeze_action(private_key)
    verify_action_signature(
        action,
        signature_field="freeze_signature",
        public_key_field="frozen_by_signing_public_key",
    )


def test_verify_action_signature_rejects_tampered_payload() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    action = _signed_report_action(private_key)
    # Build a new model that reuses the original signature but mutates the
    # ``snapshot_id`` — the canonical body changes, so verification must fail.
    payload = action.model_dump(mode="json")
    payload["snapshot_id"] = "99999999-9999-9999-9999-999999999999"
    tampered = ReportAction.model_validate(payload)
    with pytest.raises(SignatureVerificationError):
        verify_action_signature(
            tampered,
            signature_field="report_signature",
            public_key_field="reported_by_signing_public_key",
        )


def test_verify_action_signature_rejects_short_signature() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    action = _signed_report_action(private_key)
    payload = action.model_dump(mode="json")
    payload["report_signature"] = b64url_encode(b"\x00" * 63)
    short = ReportAction.model_validate(payload)
    with pytest.raises(SignatureFormatError):
        verify_action_signature(
            short,
            signature_field="report_signature",
            public_key_field="reported_by_signing_public_key",
        )


def test_verify_action_signature_rejects_wrong_pubkey() -> None:
    """A valid signature does not validate under a different key."""
    private_key_a = ec.generate_private_key(ec.SECP256R1())
    private_key_b = ec.generate_private_key(ec.SECP256R1())
    action = _signed_report_action(private_key_a)
    # Swap in B's public key while keeping A's signature.
    pubkey_b = _uncompressed_pubkey_bytes(private_key_b)
    payload = action.model_dump(mode="json")
    payload["reported_by_signing_public_key"] = b64url_encode(pubkey_b)
    swapped = ReportAction.model_validate(payload)
    with pytest.raises(SignatureVerificationError):
        verify_action_signature(
            swapped,
            signature_field="report_signature",
            public_key_field="reported_by_signing_public_key",
        )
