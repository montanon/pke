"""HKDF-SHA256 key derivation. Tentative surface."""

from __future__ import annotations

__all__ = ["hkdf_sha256"]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    raise NotImplementedError
