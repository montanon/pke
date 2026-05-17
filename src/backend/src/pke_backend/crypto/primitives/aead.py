"""AES-256-GCM AEAD primitive. Tentative surface."""

from __future__ import annotations

__all__ = ["decrypt", "encrypt"]


def encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> bytes:
    raise NotImplementedError


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes | None = None,
) -> bytes:
    raise NotImplementedError
