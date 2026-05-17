"""Tests for ``pke_backend.crypto.primitives.sign`` — fixture-only P1363 signer.

Covers HLAM-19 AC #1: the primitive emits 64-byte raw P1363 signatures that
verify against ``pke_backend.crypto.signatures.verify_signature``, and
rejects malformed inputs symmetrically with the verifier.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pke_backend.crypto.errors import SignatureFormatError
from pke_backend.crypto.primitives.sign import sign
from pke_backend.crypto.signatures import verify_signature

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "ecdsa_p256"


@pytest.fixture(scope="module")
def keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


@pytest.mark.parametrize("payload", [b"", b"x", b"\x00" * 1024])
def test_sign_returns_64_bytes(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    payload: bytes,
) -> None:
    priv, _ = keypair
    sig = sign(payload, priv)
    assert isinstance(sig, bytes)
    assert len(sig) == 64


@pytest.mark.parametrize("payload", [b"", b"hello pke", b"\x00" * 1024])
def test_sign_output_verifies(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    payload: bytes,
) -> None:
    priv, pub = keypair
    sig = sign(payload, priv)
    assert verify_signature(pub, payload, sig) is None


def test_sign_non_bytes_payload_rejected(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    priv, _ = keypair
    with pytest.raises(SignatureFormatError):
        sign("not bytes", priv)  # type: ignore[arg-type]


def test_sign_non_p256_key_rejected() -> None:
    priv = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(SignatureFormatError):
        sign(b"payload", priv)


def test_sign_wrong_key_type_rejected() -> None:
    with pytest.raises(SignatureFormatError):
        sign(b"payload", object())  # type: ignore[arg-type]


def test_sign_error_reason_does_not_leak_key_material() -> None:
    # Use a real P-384 key — its serialized bytes must not appear in the
    # error reason. The reason should reference the curve name only.
    priv = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(SignatureFormatError) as info:
        sign(b"payload", priv)
    reason = str(info.value)
    # Private scalar should never appear in the error reason.
    private_bytes = priv.private_numbers().private_value.to_bytes(48, "big")
    assert private_bytes.hex() not in reason
    assert "secp384r1" in reason.lower()


def test_sign_cross_vector_round_trips_with_verifier() -> None:
    bundle = json.loads((VECTORS_DIR / "p1-snapshot-commit.json").read_text())
    inputs = bundle["inputs"]
    assert isinstance(inputs, dict)
    pem = str(inputs["private_key_pkcs8_pem"]).encode("ascii")
    loaded = load_pem_private_key(pem, password=None)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert isinstance(loaded.curve, ec.SECP256R1)

    message = bytes.fromhex(str(inputs["message_hex"]))
    sig = sign(message, loaded)
    assert len(sig) == 64

    pub_raw = bytes.fromhex(str(inputs["public_key_uncompressed_hex"]))
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_raw)
    # ECDSA in pyca's default path is non-deterministic, so do not compare
    # against the stored signature_p1363_hex; just check the round trip.
    assert verify_signature(pub, message, sig) is None
