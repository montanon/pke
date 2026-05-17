"""AES-256-GCM AEAD primitive for the PKE protocol.

Thin wrapper over ``cryptography.hazmat.primitives.ciphers.aead.AESGCM`` that
pins the cipher to AES-256-GCM (32-byte key) with a 12-byte nonce and a
16-byte authentication tag, matching the wire convention used by iOS
``CryptoKit.AES.GCM`` (`ciphertext || tag`).

All structural problems (wrong types, wrong key length, wrong nonce length,
truncated ciphertext) raise ``AEADError`` *before* any cipher state is
constructed. Tag failures from the underlying primitive are mapped onto the
same error type so that callers never see ``cryptography``'s exceptions and
``reason`` strings never embed key, plaintext, or tag bytes.

AAD is non-optional in the signature; callers pass ``b""`` for "no AAD".
This matches the protocol shape — every key-wrap blob binds a context AAD
and the test vectors in ``src/shared/test_vectors/aes_gcm/`` parameterise
the empty case explicitly.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pke_backend.crypto.errors import AEADError

__all__ = ["aead_open", "aead_seal"]

_KEY_LENGTH = 32
_NONCE_LENGTH = 12
_TAG_LENGTH = 16


def _ensure_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise AEADError(reason=f"{name} must be bytes, got {type(value).__name__}")
    return bytes(value)


def aead_seal(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    """Seal ``plaintext`` under AES-256-GCM and return ``ciphertext || tag``.

    ``key`` MUST be 32 bytes, ``nonce`` MUST be 12 bytes, and the returned
    buffer is ``len(plaintext) + 16``. ``aad`` is non-optional; pass ``b""``
    to bind no associated data.

    Raises ``AEADError`` for any structural problem (wrong types, wrong key
    length, wrong nonce length). The underlying primitive cannot fail on
    seal once inputs are well-formed.
    """
    plaintext_b = _ensure_bytes(plaintext, "plaintext")
    key_b = _ensure_bytes(key, "key")
    nonce_b = _ensure_bytes(nonce, "nonce")
    aad_b = _ensure_bytes(aad, "aad")
    if len(key_b) != _KEY_LENGTH:
        raise AEADError(reason=f"key must be {_KEY_LENGTH} bytes, got {len(key_b)}")
    if len(nonce_b) != _NONCE_LENGTH:
        raise AEADError(reason=f"nonce must be {_NONCE_LENGTH} bytes, got {len(nonce_b)}")

    return AESGCM(key_b).encrypt(nonce_b, plaintext_b, aad_b)


def aead_open(ciphertext_and_tag: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    """Open a ``ciphertext || tag`` blob and return the plaintext.

    The trailing 16 bytes are interpreted as the GCM tag. ``key`` MUST be
    32 bytes, ``nonce`` MUST be 12 bytes, and the blob MUST be at least 16
    bytes to carry the tag.

    Raises ``AEADError`` for any structural problem before verification and
    for tag-validation failure (tampered ciphertext, tag, nonce, key, or
    AAD).
    """
    blob = _ensure_bytes(ciphertext_and_tag, "ciphertext_and_tag")
    key_b = _ensure_bytes(key, "key")
    nonce_b = _ensure_bytes(nonce, "nonce")
    aad_b = _ensure_bytes(aad, "aad")
    if len(key_b) != _KEY_LENGTH:
        raise AEADError(reason=f"key must be {_KEY_LENGTH} bytes, got {len(key_b)}")
    if len(nonce_b) != _NONCE_LENGTH:
        raise AEADError(reason=f"nonce must be {_NONCE_LENGTH} bytes, got {len(nonce_b)}")
    if len(blob) < _TAG_LENGTH:
        raise AEADError(
            reason=f"ciphertext_and_tag must be at least {_TAG_LENGTH} bytes, got {len(blob)}",
        )

    try:
        return AESGCM(key_b).decrypt(nonce_b, blob, aad_b)
    except InvalidTag as exc:
        raise AEADError(reason="authentication tag did not validate") from exc
