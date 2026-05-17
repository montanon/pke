from __future__ import annotations

import os

import pytest

from pke_backend.crypto.encoding import b64url_decode, b64url_encode, hex_decode, hex_encode
from pke_backend.crypto.errors import EncodingError

# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------


def test_b64url_encode_empty() -> None:
    assert b64url_encode(b"") == ""


def test_b64url_decode_empty() -> None:
    assert b64url_decode("") == b""


def test_b64url_known_vector_32_zero_bytes() -> None:
    encoded = b64url_encode(b"\x00" * 32)
    assert encoded == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert len(encoded) == 43
    assert "=" not in encoded
    assert b64url_decode(encoded) == b"\x00" * 32


@pytest.mark.parametrize("length", [1, 2, 3, 31, 32, 33, 64])
def test_b64url_round_trip_random_lengths(length: int) -> None:
    data = os.urandom(length)
    encoded = b64url_encode(data)
    assert "=" not in encoded
    assert "+" not in encoded
    assert "/" not in encoded
    assert b64url_decode(encoded) == data


@pytest.mark.parametrize("length", [0, 1, 2, 3, 5, 16, 32, 100])
def test_b64url_output_alphabet_only(length: int) -> None:
    encoded = b64url_encode(os.urandom(length))
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert set(encoded) <= allowed


@pytest.mark.parametrize(
    "padded",
    [
        "AAA=",
        "AA==",
        "AAAA====",
        "=",
        "AAAAAAA=",  # 7 chars + 1 pad
    ],
)
def test_b64url_decode_rejects_padding(padded: str) -> None:
    with pytest.raises(EncodingError):
        b64url_decode(padded)


@pytest.mark.parametrize(
    "bad",
    [
        "A+/B",
        "AAAA+",
        "AAAA/",
        "ab+d",
        "ab/d",
    ],
)
def test_b64url_decode_rejects_standard_alphabet(bad: str) -> None:
    with pytest.raises(EncodingError):
        b64url_decode(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "A",  # length 1
        "AAAAA",  # length 5, mod 4 == 1
        "AAAAAAAAA",  # length 9, mod 4 == 1
    ],
)
def test_b64url_decode_rejects_invalid_length(bad: str) -> None:
    with pytest.raises(EncodingError):
        b64url_decode(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "AAA\x80",
        "ÿ",
        "café",
        "AAA ",
    ],
)
def test_b64url_decode_rejects_non_ascii(bad: str) -> None:
    with pytest.raises(EncodingError):
        b64url_decode(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "AA AA",
        "AAA\n",
        "AAA\t",
        "AAA*",
        "AAA.",
        "AAA!",
    ],
)
def test_b64url_decode_rejects_misc_invalid_chars(bad: str) -> None:
    with pytest.raises(EncodingError):
        b64url_decode(bad)


def test_b64url_error_reason_does_not_leak_input() -> None:
    sample = "deadbeef+leak/material=="
    with pytest.raises(EncodingError) as exc_info:
        b64url_decode(sample)
    # The reason must not include the raw input — only counts/class hints.
    assert "deadbeef" not in str(exc_info.value)
    assert "leak" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# hex
# ---------------------------------------------------------------------------


def test_hex_encode_empty() -> None:
    assert hex_encode(b"") == ""


def test_hex_encode_simple() -> None:
    assert hex_encode(b"\x00\xff") == "00ff"


def test_hex_encode_emits_lowercase() -> None:
    assert hex_encode(bytes(range(256))) == "".join(f"{i:02x}" for i in range(256))


def test_hex_decode_empty() -> None:
    assert hex_decode("") == b""


@pytest.mark.parametrize("length", [0, 1, 2, 3, 31, 32, 33, 64])
def test_hex_round_trip(length: int) -> None:
    data = os.urandom(length)
    assert hex_decode(hex_encode(data)) == data


def test_hex_decode_accepts_uppercase() -> None:
    # Permissive on case for decode (documented in encoding.py).
    assert hex_decode("00FF") == b"\x00\xff"
    assert hex_decode("DeAdBeEf") == b"\xde\xad\xbe\xef"


def test_hex_decode_rejects_non_hex() -> None:
    with pytest.raises(EncodingError):
        hex_decode("zz")


def test_hex_decode_rejects_odd_length() -> None:
    with pytest.raises(EncodingError):
        hex_decode("0")
    with pytest.raises(EncodingError):
        hex_decode("abc")


@pytest.mark.parametrize(
    "bad",
    [
        "00 ff",
        "00\tff",
        "00\nff",
        " 00ff",
        "00ff ",
    ],
)
def test_hex_decode_rejects_whitespace(bad: str) -> None:
    with pytest.raises(EncodingError):
        hex_decode(bad)


def test_hex_decode_rejects_unicode_digits() -> None:
    with pytest.raises(EncodingError):
        hex_decode("00ÿ")


def test_hex_error_reason_does_not_leak_input() -> None:
    sample = "zzzzkeymaterial"
    with pytest.raises(EncodingError) as exc_info:
        hex_decode(sample)
    assert "zzzz" not in str(exc_info.value)
    assert "key" not in str(exc_info.value)
