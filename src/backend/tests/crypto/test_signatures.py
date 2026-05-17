"""Tests for ``pke_backend.crypto.signatures`` — strict P1363 ECDSA verify.

Covers HLAM-18 acceptance criteria 1-3 and 6 (positive + negative vector
from ``src/shared/test_vectors/ecdsa_p256/``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pke_backend.crypto.errors import SignatureFormatError, SignatureVerificationError
from pke_backend.crypto.signatures import verify_signature

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "ecdsa_p256"


@pytest.fixture(scope="module")
def keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def _sign_p1363(priv: ec.EllipticCurvePrivateKey, payload: bytes) -> bytes:
    der = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_verify_valid_p1363_returns_none(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    priv, pub = keypair
    payload = b"hello pke"
    sig = _sign_p1363(priv, payload)
    assert verify_signature(pub, payload, sig) is None


def test_verify_invalid_p1363_raises_verification_error(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    priv, pub = keypair
    payload = b"hello pke"
    sig = bytearray(_sign_p1363(priv, payload))
    sig[0] ^= 0x01  # flip a bit in r
    with pytest.raises(SignatureVerificationError):
        verify_signature(pub, payload, bytes(sig))


def test_verify_payload_mutation_raises_verification_error(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    priv, pub = keypair
    payload = b"hello pke"
    sig = _sign_p1363(priv, payload)
    with pytest.raises(SignatureVerificationError):
        verify_signature(pub, payload + b"!", sig)


def test_verify_der_input_rejected_as_format_error(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    priv, pub = keypair
    der = priv.sign(b"payload", ec.ECDSA(hashes.SHA256()))
    # DER signatures of P-256 are typically 70-72 bytes and start with 0x30.
    assert der[0] == 0x30
    assert len(der) != 64
    with pytest.raises(SignatureFormatError):
        verify_signature(pub, b"payload", der)


def test_verify_65_byte_signature_with_leading_null_rejected(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    _, pub = keypair
    sig_65 = b"\x00" + b"\x01" * 64
    with pytest.raises(SignatureFormatError):
        verify_signature(pub, b"payload", sig_65)


@pytest.mark.parametrize("bad_len", [0, 1, 32, 63, 65, 71, 128])
def test_verify_wrong_length_rejected(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    bad_len: int,
) -> None:
    _, pub = keypair
    with pytest.raises(SignatureFormatError):
        verify_signature(pub, b"payload", b"\x00" * bad_len)


def test_verify_non_bytes_signature_rejected(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    _, pub = keypair
    with pytest.raises(SignatureFormatError):
        verify_signature(pub, b"payload", "not bytes")  # type: ignore[arg-type]


def test_verify_non_p256_key_rejected() -> None:
    priv = ec.generate_private_key(ec.SECP384R1())
    pub = priv.public_key()
    with pytest.raises(SignatureFormatError):
        verify_signature(pub, b"payload", b"\x00" * 64)


def test_verify_wrong_key_type_rejected() -> None:
    with pytest.raises(SignatureFormatError):
        verify_signature(object(), b"payload", b"\x00" * 64)  # type: ignore[arg-type]


def test_verify_empty_payload_permitted(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    priv, pub = keypair
    sig = _sign_p1363(priv, b"")
    assert verify_signature(pub, b"", sig) is None


def test_verify_error_reason_does_not_leak_signature_bytes(
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
) -> None:
    _, pub = keypair
    # 80-byte buffer with recognisable bytes; reason should reference length,
    # not the buffer contents.
    sig = b"\xab" * 80
    with pytest.raises(SignatureFormatError) as info:
        verify_signature(pub, b"payload", sig)
    assert sig.hex() not in str(info.value)
    assert "80" in str(info.value)


def _load_vector(name: str) -> dict[str, object]:
    return json.loads((VECTORS_DIR / name).read_text())


def _pub_from_uncompressed(hex_pub: str) -> ec.EllipticCurvePublicKey:
    raw = bytes.fromhex(hex_pub)
    return serialization.load_der_public_key(
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw).public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )  # type: ignore[return-value]


def test_vector_verify_valid_p1363() -> None:
    bundle = _load_vector("verify-valid-p1363.json")
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    assert isinstance(inputs, dict)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(inputs["public_key_uncompressed"]))
    payload = bytes.fromhex(inputs["payload"])
    sig = bytes.fromhex(inputs["signature_p1363"])
    assert verify_signature(pub, payload, sig) is None


def test_vector_verify_der_rejected_as_format_error() -> None:
    bundle = _load_vector("verify-der-rejected.json")
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    assert isinstance(inputs, dict)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(inputs["public_key_uncompressed"]))
    payload = bytes.fromhex(inputs["payload"])
    der_sig = bytes.fromhex(inputs["signature_der"])
    with pytest.raises(SignatureFormatError):
        verify_signature(pub, payload, der_sig)
