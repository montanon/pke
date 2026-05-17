from __future__ import annotations

from collections.abc import Callable

import pytest

from pke_backend.crypto import (
    AEADError,
    CanonicalEncodingError,
    CryptoError,
    EncodingError,
    HashChainError,
    SignatureFormatError,
    SignatureVerificationError,
    WrapError,
)
from pke_backend.crypto import (
    signatures as signatures_mod,
)
from pke_backend.crypto.primitives import aead as aead_mod
from pke_backend.crypto.primitives import keywrap as keywrap_mod
from pke_backend.crypto.primitives import sign as sign_mod

SUBCLASSES: tuple[type[CryptoError], ...] = (
    CanonicalEncodingError,
    EncodingError,
    SignatureFormatError,
    SignatureVerificationError,
    HashChainError,
    AEADError,
    WrapError,
)


@pytest.fixture(scope="module")
def error_subclasses() -> tuple[type[CryptoError], ...]:
    return SUBCLASSES


StubCall = tuple[str, Callable[..., object], tuple[object, ...]]


@pytest.fixture(scope="module")
def helper_stub_calls() -> list[StubCall]:
    return [
        ("signatures.sign_payload", signatures_mod.sign_payload, (b"x", object())),
        ("signatures.verify_payload", signatures_mod.verify_payload, (b"x", b"y", object())),
    ]


@pytest.fixture(scope="module")
def primitive_stub_calls() -> list[StubCall]:
    return [
        ("primitives.sign.generate_keypair", sign_mod.generate_keypair, ()),
        ("primitives.sign.sign", sign_mod.sign, (object(), b"m")),
        ("primitives.sign.verify", sign_mod.verify, (object(), b"m", b"s")),
        ("primitives.aead.encrypt", aead_mod.encrypt, (b"k" * 32, b"n" * 12, b"p")),
        ("primitives.aead.decrypt", aead_mod.decrypt, (b"k" * 32, b"n" * 12, b"c")),
        ("primitives.keywrap.wrap", keywrap_mod.wrap, (object(), object(), b"k" * 32)),
        ("primitives.keywrap.unwrap", keywrap_mod.unwrap, (object(), object(), b"w")),
    ]
