from __future__ import annotations

import re

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
from pke_backend.crypto import errors as errors_mod

EXPECTED_NAMES = {
    "CryptoError",
    "CanonicalEncodingError",
    "EncodingError",
    "SignatureFormatError",
    "SignatureVerificationError",
    "HashChainError",
    "AEADError",
    "WrapError",
}


def test_error_taxonomy_complete() -> None:
    exported = set(errors_mod.__all__)
    assert exported == EXPECTED_NAMES
    for name in EXPECTED_NAMES:
        assert hasattr(errors_mod, name), name


def test_error_subclasses_inherit_base(
    error_subclasses: tuple[type[CryptoError], ...],
) -> None:
    assert len(error_subclasses) == 7
    for cls in error_subclasses:
        assert issubclass(cls, CryptoError)


def test_error_default_reason_is_none(
    error_subclasses: tuple[type[CryptoError], ...],
) -> None:
    for cls in error_subclasses:
        err = cls()
        assert err.reason is None
        assert str(err) == cls.__name__


def test_error_reason_round_trip(
    error_subclasses: tuple[type[CryptoError], ...],
) -> None:
    for cls in error_subclasses:
        err = cls(reason="bad padding")
        assert err.reason == "bad padding"
        assert "bad padding" in str(err)
        assert cls.__name__ in str(err)


def test_reason_slot_declared() -> None:
    assert CryptoError.__slots__ == ("reason",)
    assert "reason" in CryptoError.__dict__
    err = CryptoError()
    assert hasattr(err, "reason")
    assert err.reason is None


@pytest.mark.parametrize(
    "cls",
    [
        CanonicalEncodingError,
        EncodingError,
        SignatureFormatError,
        SignatureVerificationError,
        HashChainError,
        AEADError,
        WrapError,
    ],
)
def test_single_except_catches_all_subclasses(cls: type[CryptoError]) -> None:
    with pytest.raises(CryptoError):
        raise cls("x")


_SECRET_LIKE = re.compile(r"[A-Za-z0-9+/=_-]{40,}")


def test_no_secret_material_in_default_str() -> None:
    assert _SECRET_LIKE.search(str(CryptoError())) is None
    assert _SECRET_LIKE.search(str(CryptoError(reason=""))) is None
    assert _SECRET_LIKE.search(str(CryptoError(reason="bad padding"))) is None
