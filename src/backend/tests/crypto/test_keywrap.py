"""Parity tests for ``pke_backend.crypto.primitives.keywrap`` against
``src/shared/test_vectors/ecdh_wrap/*.json``.

Positive vectors pin the deterministic AEAD nonce, sender keypair, recipient
keypair, snapshot id, and snapshot key. They assert the produced
``nonce || ciphertext || tag`` matches ``expected.wrapped_key_hex`` exactly,
that ``shared_secret_hex``/``hkdf_info_hex``/``hkdf_aad_hex``/``wrapping_key_hex``
match the locked v0.1 derivation, and that ``unwrap`` round-trips to the
original snapshot key. The negative vector asserts ``WrapError`` on unwrap.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pke_backend.crypto.errors import WrapError
from pke_backend.crypto.kdf import hkdf_sha256
from pke_backend.crypto.primitives import keywrap

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "ecdh_wrap"

_HKDF_SALT = b"pke/v0.1/keywrap/salt"


def _load(name: str) -> dict[str, object]:
    return json.loads((VECTORS_DIR / name).read_text())


def _vectors(prefix: str) -> list[str]:
    return sorted(p.name for p in VECTORS_DIR.glob(f"{prefix}*.json"))


def _load_private(pem: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return key


def _load_public_uncompressed(hex_str: str) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(hex_str))


POSITIVE_VECTORS = _vectors("p")
NEGATIVE_VECTORS = _vectors("n")


def test_vector_directory_populated() -> None:
    assert POSITIVE_VECTORS, "expected at least one positive keywrap vector"
    assert NEGATIVE_VECTORS, "expected the negative keywrap vector"


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_positive_vector_wrap_matches(vector: str) -> None:
    bundle = _load(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    sender_priv = _load_private(str(inputs["sender_private_key_pkcs8_pem"]))
    recipient_pub = _load_public_uncompressed(str(inputs["recipient_public_key_uncompressed_hex"]))
    snapshot_id = str(inputs["snapshot_id"])
    snapshot_key = bytes.fromhex(str(inputs["snapshot_key_hex"]))
    aead_nonce = bytes.fromhex(str(inputs["aead_nonce_hex"]))

    wrapped = keywrap.wrap(
        sender_private_key=sender_priv,
        recipient_public_key=recipient_pub,
        snapshot_id=snapshot_id,
        snapshot_key=snapshot_key,
        aead_nonce=aead_nonce,
    )
    assert wrapped.hex() == expected["wrapped_key_hex"]


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_positive_vector_derivation_constants_match(vector: str) -> None:
    bundle = _load(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    sender_priv = _load_private(str(inputs["sender_private_key_pkcs8_pem"]))
    recipient_pub = _load_public_uncompressed(str(inputs["recipient_public_key_uncompressed_hex"]))
    snapshot_id_utf8 = str(inputs["snapshot_id"]).encode("utf-8")
    recipient_pub_raw = bytes.fromhex(str(inputs["recipient_public_key_uncompressed_hex"]))

    shared_secret = sender_priv.exchange(ec.ECDH(), recipient_pub)
    assert shared_secret.hex() == expected["shared_secret_hex"]

    info = (
        b"pke/v0.1/keywrap/info"
        + len(snapshot_id_utf8).to_bytes(2, "big")
        + snapshot_id_utf8
        + len(recipient_pub_raw).to_bytes(2, "big")
        + recipient_pub_raw
    )
    assert info.hex() == expected["hkdf_info_hex"]

    aad = b"pke/v0.1/keywrap/aad" + len(snapshot_id_utf8).to_bytes(2, "big") + snapshot_id_utf8
    assert aad.hex() == expected["hkdf_aad_hex"]

    wrapping_key = hkdf_sha256(shared_secret, _HKDF_SALT, info, 32)
    assert wrapping_key.hex() == expected["wrapping_key_hex"]


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_positive_vector_unwrap_round_trips(vector: str) -> None:
    bundle = _load(vector)
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    recipient_priv = _load_private(str(inputs["recipient_private_key_pkcs8_pem"]))
    sender_pub = _load_public_uncompressed(str(inputs["sender_public_key_uncompressed_hex"]))
    snapshot_id = str(inputs["snapshot_id"])
    wrapped = bytes.fromhex(str(expected["wrapped_key_hex"]))

    recovered = keywrap.unwrap(
        recipient_private_key=recipient_priv,
        sender_public_key=sender_pub,
        snapshot_id=snapshot_id,
        wrapped=wrapped,
    )
    assert recovered.hex() == inputs["snapshot_key_hex"]


@pytest.mark.parametrize("vector", NEGATIVE_VECTORS)
def test_negative_vector_unwrap_raises(vector: str) -> None:
    bundle = _load(vector)
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    recipient_priv = _load_private(str(inputs["recipient_private_key_pkcs8_pem"]))
    sender_pub = _load_public_uncompressed(str(inputs["sender_public_key_uncompressed_hex"]))
    snapshot_id = str(inputs["snapshot_id"])
    wrapped = bytes.fromhex(str(expected["wrapped_key_hex"]))

    with pytest.raises(WrapError):
        keywrap.unwrap(
            recipient_private_key=recipient_priv,
            sender_public_key=sender_pub,
            snapshot_id=snapshot_id,
            wrapped=wrapped,
        )


def test_wrap_rejects_wrong_key_length() -> None:
    sender_priv = ec.generate_private_key(ec.SECP256R1())
    recipient_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(WrapError):
        keywrap.wrap(
            sender_private_key=sender_priv,
            recipient_public_key=recipient_pub,
            snapshot_id="s",
            snapshot_key=b"\x00" * 16,
            aead_nonce=b"\x00" * 12,
        )


def test_wrap_rejects_non_p256_key() -> None:
    sender_priv = ec.generate_private_key(ec.SECP384R1())
    recipient_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(WrapError):
        keywrap.wrap(
            sender_private_key=sender_priv,  # type: ignore[arg-type]
            recipient_public_key=recipient_pub,
            snapshot_id="s",
            snapshot_key=b"\x00" * 32,
            aead_nonce=b"\x00" * 12,
        )
