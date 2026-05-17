"""HKDF-SHA256 derivation wrapper for the PKE protocol.

Thin layer over ``cryptography.hazmat.primitives.kdf.hkdf.HKDF`` that pins the
hash to SHA-256 and exposes the RFC 5869 parameter order used elsewhere in
the spec. See ``context/16_canonical_encoding.md`` (HKDF section) for the
locked snapshot-key-wrap labels.

Per RFC 5869, both ``salt`` and ``info`` may be empty, and the maximum
output length is ``255 * HashLen`` — 8160 bytes for SHA-256.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["hkdf_sha256"]

_HASH_LEN = 32
_MAX_LENGTH = 255 * _HASH_LEN


def hkdf_sha256(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Derive ``length`` bytes from ``secret`` via HKDF-SHA256 (RFC 5869).

    ``salt`` and ``info`` may be empty. ``length`` must satisfy
    ``1 <= length <= 255 * 32`` per the RFC's output cap.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError(f"secret must be bytes, got {type(secret).__name__}")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt must be bytes, got {type(salt).__name__}")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError(f"info must be bytes, got {type(info).__name__}")
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"length must be int, got {type(length).__name__}")
    if length < 1 or length > _MAX_LENGTH:
        raise ValueError(f"length must be in [1, {_MAX_LENGTH}] per RFC 5869, got {length}")

    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=bytes(salt),
        info=bytes(info),
    )
    return kdf.derive(bytes(secret))
