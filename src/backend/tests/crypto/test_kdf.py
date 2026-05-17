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


def _build_info(snapshot_id: str, recipient_pub_hex: str) -> bytes:
    sid = snapshot_id.encode("utf-8")
    pub = bytes.fromhex(recipient_pub_hex)
    return b"pke/v0.1/keywrap/info" + len(sid).to_bytes(2, "big") + sid + len(pub).to_bytes(2, "big") + pub


POSITIVE_VECTORS = ("p1-snap0001-r1.json", "p2-snap0001-r2.json", "p3-snap0002-r1.json")


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_vector_positive_keywrap_matches(vector: str) -> None:
    """Each positive vector ships salt/info bytes and the expected OKM.

    The contract: an implementation that ingests ``inputs`` and constructs
    ``info`` per HLAM-3 must produce ``expected.info_hex`` byte-for-byte
    and derive ``expected.okm_hex`` from that.
    """
    bundle = _load_vector(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    info = _build_info(str(inputs["snapshot_id"]), str(inputs["recipient_public_key_hex"]))
    assert info.hex() == expected["info_hex"]
    okm = hkdf_sha256(
        bytes.fromhex(str(inputs["ikm_hex"])),
        bytes.fromhex(str(expected["salt_hex"])),
        info,
        32,
    )
    assert okm.hex() == expected["okm_hex"]


def test_vector_negative_wrong_info_bytes_mismatches() -> None:
    """n1 corrupts ``expected.info_hex`` while keeping the recorded ``okm_hex``
    aligned with the matching positive. Rebuilding ``info`` from the clean
    ``inputs`` MUST produce bytes that do NOT match the corrupted
    ``expected.info_hex`` — surfacing the tamper.
    """
    bundle = _load_vector("n1-wrong-info-bytes.json")
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    info = _build_info(str(inputs["snapshot_id"]), str(inputs["recipient_public_key_hex"]))
    assert info.hex() != expected["info_hex"]
    okm = hkdf_sha256(
        bytes.fromhex(str(inputs["ikm_hex"])),
        bytes.fromhex(str(expected["salt_hex"])),
        info,
        32,
    )
    # OKM derived from clean inputs equals the recorded reference; only the
    # corrupted info_hex diverges.
    assert okm.hex() == expected["okm_hex"]
