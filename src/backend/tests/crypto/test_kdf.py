"""Tests for ``pke_backend.crypto.kdf`` — HKDF-SHA256 wrapper.

Covers HLAM-18 acceptance criteria 4-6 (length determinism, locked-input
parity with iOS via stored vectors, wrong-info negative).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pke_backend.crypto.kdf import hkdf_sha256

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "hkdf_sha256"

_MAX_OUTPUT = 255 * 32


def test_returns_requested_length() -> None:
    for length in (1, 16, 32, 64, 200, _MAX_OUTPUT):
        out = hkdf_sha256(b"secret", b"salt", b"info", length)
        assert isinstance(out, bytes)
        assert len(out) == length


def test_empty_salt_permitted() -> None:
    out = hkdf_sha256(b"secret", b"", b"info", 32)
    assert len(out) == 32


def test_empty_info_permitted() -> None:
    out = hkdf_sha256(b"secret", b"salt", b"", 32)
    assert len(out) == 32


def test_empty_salt_and_info_permitted() -> None:
    out = hkdf_sha256(b"secret", b"", b"", 32)
    assert len(out) == 32


def test_deterministic_for_same_inputs() -> None:
    a = hkdf_sha256(b"k", b"s", b"i", 64)
    b = hkdf_sha256(b"k", b"s", b"i", 64)
    assert a == b


@pytest.mark.parametrize(
    "mutator",
    [
        lambda s, sa, i, n: (b"K", sa, i, n),
        lambda s, sa, i, n: (s, b"S", i, n),
        lambda s, sa, i, n: (s, sa, b"I", n),
    ],
)
def test_any_input_change_changes_output(mutator) -> None:  # type: ignore[no-untyped-def]
    base = (b"k", b"s", b"i", 32)
    mutated = mutator(*base)
    assert hkdf_sha256(*base) != hkdf_sha256(*mutated)


def test_length_above_rfc_cap_rejected() -> None:
    with pytest.raises(ValueError):
        hkdf_sha256(b"k", b"s", b"i", _MAX_OUTPUT + 1)


@pytest.mark.parametrize("bad", [0, -1])
def test_length_below_one_rejected(bad: int) -> None:
    with pytest.raises(ValueError):
        hkdf_sha256(b"k", b"s", b"i", bad)


def test_bool_length_rejected() -> None:
    # bool is an int subclass but never sensible here.
    with pytest.raises(TypeError):
        hkdf_sha256(b"k", b"s", b"i", True)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["secret", "salt", "info"])
def test_non_bytes_input_rejected(field: str) -> None:
    kwargs: dict[str, object] = {
        "secret": b"k",
        "salt": b"s",
        "info": b"i",
        "length": 32,
    }
    kwargs[field] = "not bytes"
    with pytest.raises(TypeError):
        hkdf_sha256(**kwargs)  # type: ignore[arg-type]


def test_rfc5869_test_case_1() -> None:
    """RFC 5869 Appendix A.1 — basic SHA-256 vector."""
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42
    expected = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    assert hkdf_sha256(ikm, salt, info, length) == expected


def test_rfc5869_test_case_3_empty_salt_and_info() -> None:
    """RFC 5869 Appendix A.3 — SHA-256 with empty salt and empty info."""
    ikm = bytes.fromhex("0b" * 22)
    expected = bytes.fromhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    assert hkdf_sha256(ikm, b"", b"", 42) == expected


def _load_vector(name: str) -> dict[str, object]:
    return json.loads((VECTORS_DIR / name).read_text())


def test_vector_keywrap_positive() -> None:
    bundle = _load_vector("derive-keywrap-32.json")
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    out = hkdf_sha256(
        bytes.fromhex(inputs["secret"]),
        bytes.fromhex(inputs["salt"]),
        bytes.fromhex(inputs["info"]),
        int(inputs["length"]),
    )
    assert out.hex() == expected["okm"]


def test_vector_wrong_info_mismatch() -> None:
    bundle = _load_vector("derive-wrong-info-mismatch.json")
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    assert isinstance(inputs, dict)
    out = hkdf_sha256(
        bytes.fromhex(inputs["secret"]),
        bytes.fromhex(inputs["salt"]),
        bytes.fromhex(inputs["info"]),
        int(inputs["length"]),
    )
    # The contract: same secret/salt with mutated info produces different OKM
    # than the reference (positive vector) OKM.
    assert out.hex() != inputs["reference_okm"]
