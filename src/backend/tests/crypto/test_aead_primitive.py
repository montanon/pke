"""Tests for ``pke_backend.crypto.primitives.aead`` — AES-256-GCM wrapper.

Covers HLAM-19 acceptance criteria 2-4 (roundtrip, structural rejection,
tag-failure mapping) plus the locked vectors in
``src/shared/test_vectors/aes_gcm/``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pke_backend.crypto.errors import AEADError
from pke_backend.crypto.primitives.aead import aead_open, aead_seal

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "aes_gcm"

_KEY = b"k" * 32
_NONCE = b"n" * 12
_AAD = b"context"
_TAG_LENGTH = 16


@pytest.mark.parametrize(
    ("plaintext", "aad"),
    [
        (b"", b""),
        (b"", _AAD),
        (b"A", b""),
        (b"A", _AAD),
        (os.urandom(1024), b""),
        (os.urandom(1024), _AAD),
    ],
)
def test_roundtrip_returns_original_plaintext(plaintext: bytes, aad: bytes) -> None:
    blob = aead_seal(plaintext, _KEY, _NONCE, aad)
    assert aead_open(blob, _KEY, _NONCE, aad) == plaintext


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1024])
def test_output_is_plaintext_plus_tag(size: int) -> None:
    plaintext = os.urandom(size)
    blob = aead_seal(plaintext, _KEY, _NONCE, _AAD)
    assert len(blob) == size + _TAG_LENGTH


def test_wrong_key_raises_aead_error() -> None:
    blob = aead_seal(b"payload", _KEY, _NONCE, _AAD)
    other_key = bytes(b ^ 0xFF for b in _KEY)
    with pytest.raises(AEADError):
        aead_open(blob, other_key, _NONCE, _AAD)


def test_wrong_nonce_raises_aead_error() -> None:
    blob = aead_seal(b"payload", _KEY, _NONCE, _AAD)
    other_nonce = bytes(b ^ 0xFF for b in _NONCE)
    with pytest.raises(AEADError):
        aead_open(blob, _KEY, other_nonce, _AAD)


def test_wrong_aad_raises_aead_error() -> None:
    blob = aead_seal(b"payload", _KEY, _NONCE, _AAD)
    with pytest.raises(AEADError):
        aead_open(blob, _KEY, _NONCE, _AAD + b"!")


def test_flipped_ciphertext_byte_raises_aead_error() -> None:
    blob = bytearray(aead_seal(b"payload-data", _KEY, _NONCE, _AAD))
    # Flip a byte in the ciphertext region (anything before the trailing tag).
    blob[0] ^= 0x01
    with pytest.raises(AEADError):
        aead_open(bytes(blob), _KEY, _NONCE, _AAD)


def test_flipped_tag_byte_raises_aead_error() -> None:
    blob = bytearray(aead_seal(b"payload-data", _KEY, _NONCE, _AAD))
    # Flip a byte inside the trailing 16-byte tag.
    blob[-1] ^= 0x01
    with pytest.raises(AEADError):
        aead_open(bytes(blob), _KEY, _NONCE, _AAD)


@pytest.mark.parametrize("size", [0, 1, 8, 15])
def test_truncated_blob_below_tag_length_rejected(size: int) -> None:
    with pytest.raises(AEADError):
        aead_open(b"\x00" * size, _KEY, _NONCE, _AAD)


@pytest.mark.parametrize("bad_len", [0, 1, 16, 24, 31, 33, 64])
def test_seal_bad_key_length_rejected(bad_len: int) -> None:
    with pytest.raises(AEADError):
        aead_seal(b"pt", b"\x00" * bad_len, _NONCE, _AAD)


@pytest.mark.parametrize("bad_len", [0, 1, 8, 11, 13, 16, 24])
def test_seal_bad_nonce_length_rejected(bad_len: int) -> None:
    with pytest.raises(AEADError):
        aead_seal(b"pt", _KEY, b"\x00" * bad_len, _AAD)


@pytest.mark.parametrize("bad_len", [0, 1, 16, 31, 33])
def test_open_bad_key_length_rejected(bad_len: int) -> None:
    blob = aead_seal(b"pt", _KEY, _NONCE, _AAD)
    with pytest.raises(AEADError):
        aead_open(blob, b"\x00" * bad_len, _NONCE, _AAD)


@pytest.mark.parametrize("bad_len", [0, 1, 8, 11, 13, 16])
def test_open_bad_nonce_length_rejected(bad_len: int) -> None:
    blob = aead_seal(b"pt", _KEY, _NONCE, _AAD)
    with pytest.raises(AEADError):
        aead_open(blob, _KEY, b"\x00" * bad_len, _AAD)


@pytest.mark.parametrize("field", ["plaintext", "key", "nonce", "aad"])
def test_seal_non_bytes_inputs_rejected(field: str) -> None:
    kwargs: dict[str, object] = {
        "plaintext": b"pt",
        "key": _KEY,
        "nonce": _NONCE,
        "aad": _AAD,
    }
    kwargs[field] = "not bytes"
    with pytest.raises(AEADError):
        aead_seal(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["ciphertext_and_tag", "key", "nonce", "aad"])
def test_open_non_bytes_inputs_rejected(field: str) -> None:
    blob = aead_seal(b"pt", _KEY, _NONCE, _AAD)
    kwargs: dict[str, object] = {
        "ciphertext_and_tag": blob,
        "key": _KEY,
        "nonce": _NONCE,
        "aad": _AAD,
    }
    kwargs[field] = "not bytes"
    with pytest.raises(AEADError):
        aead_open(**kwargs)  # type: ignore[arg-type]


def test_seal_bytearray_inputs_accepted() -> None:
    blob = aead_seal(bytearray(b"pt"), bytearray(_KEY), bytearray(_NONCE), bytearray(_AAD))
    assert aead_open(bytearray(blob), bytearray(_KEY), bytearray(_NONCE), bytearray(_AAD)) == b"pt"


def _load_vector(name: str) -> dict[str, object]:
    return json.loads((VECTORS_DIR / name).read_text())


def _vector_files(prefix: str) -> list[str]:
    return sorted(p.name for p in VECTORS_DIR.glob(f"{prefix}*.json"))


@pytest.mark.parametrize("vector", _vector_files("p"))
def test_vector_positive_seal_and_open_match(vector: str) -> None:
    bundle = _load_vector(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    key = bytes.fromhex(str(inputs["key_hex"]))
    nonce = bytes.fromhex(str(inputs["nonce_hex"]))
    aad = bytes.fromhex(str(inputs["aad_hex"]))
    plaintext = bytes.fromhex(str(inputs["plaintext_hex"]))
    expected_blob = bytes.fromhex(str(expected["ciphertext_hex"])) + bytes.fromhex(str(expected["tag_hex"]))

    sealed = aead_seal(plaintext, key, nonce, aad)
    assert sealed == expected_blob
    assert aead_open(expected_blob, key, nonce, aad) == plaintext


@pytest.mark.parametrize("vector", _vector_files("n"))
def test_vector_negative_open_raises_aead_error(vector: str) -> None:
    bundle = _load_vector(vector)
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    key = bytes.fromhex(str(inputs["key_hex"]))
    nonce = bytes.fromhex(str(inputs["nonce_hex"]))
    aad = bytes.fromhex(str(inputs["aad_hex"]))
    blob = bytes.fromhex(str(expected["ciphertext_hex"])) + bytes.fromhex(str(expected["tag_hex"]))

    with pytest.raises(AEADError):
        aead_open(blob, key, nonce, aad)
