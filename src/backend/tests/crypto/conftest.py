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
