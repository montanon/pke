"""AES-256-GCM AEAD primitive (test-only).

Locked to AES-256 (32-byte key), 96-bit (12-byte) nonce, untruncated 128-bit
(16-byte) tag per ``context/16_canonical_encoding.md`` §AES-256-GCM. The wire
layout for higher-level callers is ``nonce || ciphertext || tag``; this
primitive returns and consumes ``ciphertext || tag`` and leaves nonce framing
to the caller.

Import is restricted to ``src/backend/tests/**`` and ``src/shared/tools/**``
by the ruff banned-api rule and the AST boundary test.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pke_backend.crypto.errors import AEADError

__all__ = ["decrypt", "encrypt"]

_KEY_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16


def _check_inputs(key: bytes, nonce: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise AEADError(reason=f"key must be bytes, got {type(key).__name__}")
    if len(key) != _KEY_LEN:
        raise AEADError(reason=f"expected {_KEY_LEN}-byte AES-256 key, got {len(key)} bytes")
    if not isinstance(nonce, (bytes, bytearray)):
        raise AEADError(reason=f"nonce must be bytes, got {type(nonce).__name__}")
    if len(nonce) != _NONCE_LEN:
        raise AEADError(reason=f"expected {_NONCE_LEN}-byte nonce, got {len(nonce)} bytes")


def encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Encrypt ``plaintext`` with AES-256-GCM. Returns ``ciphertext || tag``."""
    _check_inputs(key, nonce)
    if not isinstance(plaintext, (bytes, bytearray)):
        raise AEADError(reason=f"plaintext must be bytes, got {type(plaintext).__name__}")
    if aad is not None and not isinstance(aad, (bytes, bytearray)):
        raise AEADError(reason=f"aad must be bytes or None, got {type(aad).__name__}")
    return AESGCM(bytes(key)).encrypt(bytes(nonce), bytes(plaintext), bytes(aad) if aad is not None else None)


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt ``ciphertext || tag`` with AES-256-GCM. Raises ``AEADError`` on auth failure."""
    _check_inputs(key, nonce)
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise AEADError(reason=f"ciphertext must be bytes, got {type(ciphertext).__name__}")
    if len(ciphertext) < _TAG_LEN:
        raise AEADError(reason=f"ciphertext shorter than {_TAG_LEN}-byte tag: {len(ciphertext)} bytes")
    if aad is not None and not isinstance(aad, (bytes, bytearray)):
        raise AEADError(reason=f"aad must be bytes or None, got {type(aad).__name__}")
    try:
        return AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext), bytes(aad) if aad is not None else None)
    except InvalidTag as exc:
        raise AEADError(reason="AES-GCM tag verification failed") from exc
