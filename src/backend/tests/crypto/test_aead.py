"""Parity tests for ``pke_backend.crypto.primitives.aead`` against
``src/shared/test_vectors/aes_gcm/*.json``.

Positive bundles assert byte-identical ``ciphertext || tag`` and a successful
decrypt round-trip. The single negative bundle asserts that AEAD tag
verification raises ``AEADError`` on decrypt.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pke_backend.crypto.errors import AEADError
from pke_backend.crypto.primitives import aead

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "aes_gcm"


def _load(name: str) -> dict[str, object]:
    return json.loads((VECTORS_DIR / name).read_text())


def _vectors(prefix: str) -> list[str]:
    return sorted(p.name for p in VECTORS_DIR.glob(f"{prefix}*.json"))


POSITIVE_VECTORS = _vectors("p")
NEGATIVE_VECTORS = _vectors("n")


def test_vector_directory_populated() -> None:
    assert POSITIVE_VECTORS, "expected at least one positive AES-GCM vector"
    assert NEGATIVE_VECTORS, "expected the negative AES-GCM vector"


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_positive_vector_encrypt_matches(vector: str) -> None:
    bundle = _load(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    key = bytes.fromhex(str(inputs["key_hex"]))
    nonce = bytes.fromhex(str(inputs["nonce_hex"]))
    aad = bytes.fromhex(str(inputs["aad_hex"]))
    plaintext = bytes.fromhex(str(inputs["plaintext_hex"]))
    expected_ct_and_tag = bytes.fromhex(str(expected["ciphertext_hex"]) + str(expected["tag_hex"]))

    out = aead.encrypt(key, nonce, plaintext, aad or None)
    assert out == expected_ct_and_tag


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_positive_vector_decrypt_round_trips(vector: str) -> None:
    bundle = _load(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    key = bytes.fromhex(str(inputs["key_hex"]))
    nonce = bytes.fromhex(str(inputs["nonce_hex"]))
    aad = bytes.fromhex(str(inputs["aad_hex"]))
    ct_and_tag = bytes.fromhex(str(expected["ciphertext_hex"]) + str(expected["tag_hex"]))

    plaintext = aead.decrypt(key, nonce, ct_and_tag, aad or None)
    assert plaintext == bytes.fromhex(str(inputs["plaintext_hex"]))


@pytest.mark.parametrize("vector", NEGATIVE_VECTORS)
def test_negative_vector_decrypt_raises(vector: str) -> None:
    bundle = _load(vector)
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    key = bytes.fromhex(str(inputs["key_hex"]))
    nonce = bytes.fromhex(str(inputs["nonce_hex"]))
    aad = bytes.fromhex(str(inputs["aad_hex"]))
    ct_and_tag = bytes.fromhex(str(expected["ciphertext_hex"]) + str(expected["tag_hex"]))

    with pytest.raises(AEADError):
        aead.decrypt(key, nonce, ct_and_tag, aad or None)


def test_key_length_validation_raises() -> None:
    with pytest.raises(AEADError):
        aead.encrypt(b"\x00" * 16, b"\x00" * 12, b"hi", None)


def test_nonce_length_validation_raises() -> None:
    with pytest.raises(AEADError):
        aead.encrypt(b"\x00" * 32, b"\x00" * 8, b"hi", None)


def test_short_ciphertext_rejected() -> None:
    with pytest.raises(AEADError):
        aead.decrypt(b"\x00" * 32, b"\x00" * 12, b"\x00" * 8, None)
