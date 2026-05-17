"""Unified crypto error taxonomy mirroring Swift `PKECrypto.CryptoError` (cryptographic subset).

The `reason` payload must NEVER contain key bytes, plaintext, or signature material.
"""

from __future__ import annotations

__all__ = [
    "AEADError",
    "CanonicalEncodingError",
    "CryptoError",
    "EncodingError",
    "HashChainError",
    "SignatureFormatError",
    "SignatureVerificationError",
    "WrapError",
]


class CryptoError(Exception):
    # __slots__ declares storage for `reason`; it cannot block attribute drift
    # because BaseException ships `__dict__`. Kept for storage-declaration clarity.
    __slots__ = ("reason",)

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason

    def __str__(self) -> str:
        if self.reason is None:
            return type(self).__name__
        return f"{type(self).__name__}: {self.reason}"


class CanonicalEncodingError(CryptoError):
    __slots__ = ()


class EncodingError(CryptoError):
    __slots__ = ()


class SignatureFormatError(CryptoError):
    __slots__ = ()


class SignatureVerificationError(CryptoError):
    __slots__ = ()


class HashChainError(CryptoError):
    __slots__ = ()


class AEADError(CryptoError):
    __slots__ = ()


class WrapError(CryptoError):
    __slots__ = ()
