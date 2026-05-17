"""Tests for ``pke_backend.crypto.primitives.keywrap`` — ECDH+HKDF+AES-GCM wrap.

Covers HLAM-19 acceptance criteria 5-7: roundtrip, determinism with a pinned
nonce, output length, AEAD failure on tamper / wrong key / wrong snapshot_id,
structural validation, and cross-check against the committed
``src/shared/test_vectors/ecdh_wrap/`` fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pke_backend.crypto.errors import AEADError, WrapError
from pke_backend.crypto.primitives.keywrap import (
    unwrap_snapshot_key,
    wrap_snapshot_key,
)

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "ecdh_wrap"

_SNAPSHOT_KEY = b"\x11" * 32
_SNAPSHOT_ID = "snap-test"
_PINNED_NONCE = bytes.fromhex("a264ff0a8ed7762ccba985dd")


def _fresh_p256() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


@pytest.fixture
def keypairs() -> tuple[
    ec.EllipticCurvePrivateKey,
    ec.EllipticCurvePublicKey,
    ec.EllipticCurvePrivateKey,
    ec.EllipticCurvePublicKey,
]:
    owner_priv, owner_pub = _fresh_p256()
    recipient_priv, recipient_pub = _fresh_p256()
    return owner_priv, owner_pub, recipient_priv, recipient_pub


def test_roundtrip_returns_original_snapshot_key(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, owner_pub, recipient_priv, recipient_pub = keypairs
    wrapped = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    out = unwrap_snapshot_key(wrapped, recipient_priv, owner_pub, _SNAPSHOT_ID)
    assert out == _SNAPSHOT_KEY


def test_wrap_output_is_60_bytes(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, _, _, recipient_pub = keypairs
    wrapped = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    assert len(wrapped) == 60


def test_wrap_is_deterministic_with_pinned_nonce(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, _, _, recipient_pub = keypairs
    a = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID, nonce=_PINNED_NONCE)
    b = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID, nonce=_PINNED_NONCE)
    assert a == b
    assert a[:12] == _PINNED_NONCE


def test_wrap_default_nonce_is_random(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, _, _, recipient_pub = keypairs
    a = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    b = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    assert a != b
    assert a[:12] != b[:12]


def test_unwrap_with_wrong_snapshot_id_raises_aead_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, owner_pub, recipient_priv, recipient_pub = keypairs
    wrapped = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    with pytest.raises(AEADError):
        unwrap_snapshot_key(wrapped, recipient_priv, owner_pub, _SNAPSHOT_ID + "-other")


def test_unwrap_with_wrong_recipient_private_key_raises_aead_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, owner_pub, _, recipient_pub = keypairs
    wrapped = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    other_priv, _ = _fresh_p256()
    with pytest.raises(AEADError):
        unwrap_snapshot_key(wrapped, other_priv, owner_pub, _SNAPSHOT_ID)


def test_unwrap_with_wrong_owner_public_key_raises_aead_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, _, recipient_priv, recipient_pub = keypairs
    wrapped = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    _, other_pub = _fresh_p256()
    with pytest.raises(AEADError):
        unwrap_snapshot_key(wrapped, recipient_priv, other_pub, _SNAPSHOT_ID)


def test_unwrap_with_tampered_ciphertext_byte_raises_aead_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, owner_pub, recipient_priv, recipient_pub = keypairs
    wrapped = bytearray(wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID))
    # Flip a bit inside the ciphertext region (offsets 12..44).
    wrapped[20] ^= 0x01
    with pytest.raises(AEADError):
        unwrap_snapshot_key(bytes(wrapped), recipient_priv, owner_pub, _SNAPSHOT_ID)


def test_unwrap_with_tampered_tag_byte_raises_aead_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, owner_pub, recipient_priv, recipient_pub = keypairs
    wrapped = bytearray(wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID))
    # Flip a bit in the trailing 16-byte tag region (offsets 44..60).
    wrapped[-1] ^= 0x01
    with pytest.raises(AEADError):
        unwrap_snapshot_key(bytes(wrapped), recipient_priv, owner_pub, _SNAPSHOT_ID)


@pytest.mark.parametrize("bad_len", [0, 1, 31, 33, 64])
def test_wrap_snapshot_key_wrong_length_raises_wrap_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
    bad_len: int,
) -> None:
    owner_priv, _, _, recipient_pub = keypairs
    with pytest.raises(WrapError):
        wrap_snapshot_key(b"\x00" * bad_len, owner_priv, recipient_pub, _SNAPSHOT_ID)


def test_wrap_non_bytes_snapshot_key_raises_wrap_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, _, _, recipient_pub = keypairs
    with pytest.raises(WrapError):
        wrap_snapshot_key("not bytes", owner_priv, recipient_pub, _SNAPSHOT_ID)  # type: ignore[arg-type]


def test_wrap_non_str_snapshot_id_raises_wrap_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, _, _, recipient_pub = keypairs
    with pytest.raises(WrapError):
        wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, b"bytes")  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_nonce_len", [0, 1, 11, 13, 16])
def test_wrap_wrong_nonce_length_raises_wrap_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
    bad_nonce_len: int,
) -> None:
    owner_priv, _, _, recipient_pub = keypairs
    with pytest.raises(WrapError):
        wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID, nonce=b"\x00" * bad_nonce_len)


@pytest.mark.parametrize("bad_len", [0, 1, 59, 61, 120])
def test_unwrap_wrong_length_raises_wrap_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
    bad_len: int,
) -> None:
    _, owner_pub, recipient_priv, _ = keypairs
    with pytest.raises(WrapError):
        unwrap_snapshot_key(b"\x00" * bad_len, recipient_priv, owner_pub, _SNAPSHOT_ID)


def test_unwrap_non_bytes_wrapped_raises_wrap_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    _, owner_pub, recipient_priv, _ = keypairs
    with pytest.raises(WrapError):
        unwrap_snapshot_key("not bytes", recipient_priv, owner_pub, _SNAPSHOT_ID)  # type: ignore[arg-type]


def test_wrap_wrong_curve_owner_key_raises_wrap_error() -> None:
    owner_priv_wrong = ec.generate_private_key(ec.SECP384R1())
    _, recipient_pub = _fresh_p256()
    with pytest.raises(WrapError):
        wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv_wrong, recipient_pub, _SNAPSHOT_ID)


def test_wrap_wrong_curve_recipient_key_raises_wrap_error() -> None:
    owner_priv, _ = _fresh_p256()
    recipient_pub_wrong = ec.generate_private_key(ec.SECP384R1()).public_key()
    with pytest.raises(WrapError):
        wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub_wrong, _SNAPSHOT_ID)


def test_unwrap_wrong_curve_recipient_key_raises_wrap_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, owner_pub, _, recipient_pub = keypairs
    wrapped = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    recipient_priv_wrong = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(WrapError):
        unwrap_snapshot_key(wrapped, recipient_priv_wrong, owner_pub, _SNAPSHOT_ID)


def test_unwrap_wrong_curve_owner_pub_raises_wrap_error(
    keypairs: tuple[
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        ec.EllipticCurvePublicKey,
    ],
) -> None:
    owner_priv, _, recipient_priv, recipient_pub = keypairs
    wrapped = wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, recipient_pub, _SNAPSHOT_ID)
    owner_pub_wrong = ec.generate_private_key(ec.SECP384R1()).public_key()
    with pytest.raises(WrapError):
        unwrap_snapshot_key(wrapped, recipient_priv, owner_pub_wrong, _SNAPSHOT_ID)


def test_wrap_non_key_objects_raise_wrap_error() -> None:
    _, recipient_pub = _fresh_p256()
    with pytest.raises(WrapError):
        wrap_snapshot_key(_SNAPSHOT_KEY, object(), recipient_pub, _SNAPSHOT_ID)  # type: ignore[arg-type]
    owner_priv, _ = _fresh_p256()
    with pytest.raises(WrapError):
        wrap_snapshot_key(_SNAPSHOT_KEY, owner_priv, object(), _SNAPSHOT_ID)  # type: ignore[arg-type]


def _load_vector(name: str) -> dict[str, object]:
    return json.loads((VECTORS_DIR / name).read_text())


def _load_priv(pem: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return key


POSITIVE_VECTORS = ("p1-snapshared-r1.json", "p2-snapshared-r2.json")


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_vector_positive_wrap_matches_and_roundtrips(vector: str) -> None:
    bundle = _load_vector(vector)
    assert bundle["valid"] is True
    inputs = cast("dict[str, object]", bundle["inputs"])
    expected = cast("dict[str, object]", bundle["expected"])

    snapshot_id = str(inputs["snapshot_id"])
    snapshot_key = bytes.fromhex(str(inputs["snapshot_key_hex"]))
    sender_priv = _load_priv(str(inputs["sender_private_key_pkcs8_pem"]))
    recipient_priv = _load_priv(str(inputs["recipient_private_key_pkcs8_pem"]))
    sender_pub = sender_priv.public_key()
    recipient_pub = recipient_priv.public_key()
    nonce = bytes.fromhex(str(inputs["aead_nonce_hex"]))

    wrapped = wrap_snapshot_key(snapshot_key, sender_priv, recipient_pub, snapshot_id, nonce=nonce)
    assert wrapped.hex() == expected["wrapped_key_hex"]

    out = unwrap_snapshot_key(wrapped, recipient_priv, sender_pub, snapshot_id)
    assert out == snapshot_key


def test_vector_negative_corrupted_wrapped_key_fails_aead() -> None:
    bundle = _load_vector("n1-corrupted-wrapped-key.json")
    assert bundle["valid"] is False
    inputs = cast("dict[str, object]", bundle["inputs"])
    expected = cast("dict[str, object]", bundle["expected"])

    snapshot_id = str(inputs["snapshot_id"])
    sender_priv = _load_priv(str(inputs["sender_private_key_pkcs8_pem"]))
    recipient_priv = _load_priv(str(inputs["recipient_private_key_pkcs8_pem"]))
    sender_pub = sender_priv.public_key()

    wrapped = bytes.fromhex(str(expected["wrapped_key_hex"]))
    assert len(wrapped) == 60
    with pytest.raises(AEADError):
        unwrap_snapshot_key(wrapped, recipient_priv, sender_pub, snapshot_id)
