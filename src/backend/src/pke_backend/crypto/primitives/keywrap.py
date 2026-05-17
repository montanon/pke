"""ECDH(P-256) + HKDF-SHA256 + AES-256-GCM snapshot-key wrap primitive (test-only).

Pins the v0.1 construction from ``context/16_canonical_encoding.md`` §HKDF-SHA256
(snapshot key wrap):

  shared_secret = ECDH(sender_priv, recipient_pub)
  wrapping_key  = HKDF(secret=shared_secret,
                       salt=b"pke/v0.1/keywrap/salt",
                       info=b"pke/v0.1/keywrap/info"
                            || u16be(len(snapshot_id_utf8)) || snapshot_id_utf8
                            || u16be(len(recipient_pub_raw)) || recipient_pub_raw,
                       length=32)
  aad           = b"pke/v0.1/keywrap/aad"
                  || u16be(len(snapshot_id_utf8)) || snapshot_id_utf8
  wrapped       = nonce || AES-256-GCM_Encrypt(key=wrapping_key,
                                               nonce=nonce,
                                               plaintext=snapshot_key,
                                               aad=aad)

Import is restricted to ``src/backend/tests/**`` and ``src/shared/tools/**``
by the ruff banned-api rule and the AST boundary test.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pke_backend.crypto.errors import WrapError
from pke_backend.crypto.kdf import hkdf_sha256
from pke_backend.crypto.primitives import aead as _aead

__all__ = ["unwrap", "wrap"]

_HKDF_SALT = b"pke/v0.1/keywrap/salt"
_HKDF_INFO_PREFIX = b"pke/v0.1/keywrap/info"
_AAD_PREFIX = b"pke/v0.1/keywrap/aad"
_WRAPPING_KEY_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_SNAPSHOT_KEY_LEN = 32
_PUB_RAW_LEN = 65


def _u16be(n: int) -> bytes:
    if n < 0 or n > 0xFFFF:
        raise WrapError(reason=f"u16be input out of range: {n}")
    return n.to_bytes(2, "big")


def _recipient_pub_raw(recipient_public_key: ec.EllipticCurvePublicKey) -> bytes:
    raw = recipient_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if len(raw) != _PUB_RAW_LEN:
        raise WrapError(reason=f"recipient public key must be {_PUB_RAW_LEN}-byte uncompressed point, got {len(raw)}")
    return raw


def _check_p256(key: object, name: str) -> None:
    if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        raise WrapError(reason=f"{name} must be an EC private/public key, got {type(key).__name__}")
    if not isinstance(key.curve, ec.SECP256R1):
        raise WrapError(reason=f"{name} must use P-256, got curve {key.curve.name}")


def _derive_wrapping_key(
    *,
    own_private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
    recipient_public_key: ec.EllipticCurvePublicKey,
    snapshot_id: str,
) -> tuple[bytes, bytes]:
    """Return ``(wrapping_key, aad)`` for the v0.1 construction.

    ``own_private_key``/``peer_public_key`` are the two ECDH endpoints from the
    caller's perspective; ``recipient_public_key`` is the recipient regardless
    of which side is calling, because the HKDF ``info`` is always bound to the
    recipient's public key per ``context/16_canonical_encoding.md``.
    """
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise WrapError(reason="snapshot_id must be a non-empty string")
    snapshot_id_utf8 = snapshot_id.encode("utf-8")
    pub_raw = _recipient_pub_raw(recipient_public_key)

    shared_secret = own_private_key.exchange(ec.ECDH(), peer_public_key)
    info = _HKDF_INFO_PREFIX + _u16be(len(snapshot_id_utf8)) + snapshot_id_utf8 + _u16be(len(pub_raw)) + pub_raw
    wrapping_key = hkdf_sha256(shared_secret, _HKDF_SALT, info, _WRAPPING_KEY_LEN)
    aad = _AAD_PREFIX + _u16be(len(snapshot_id_utf8)) + snapshot_id_utf8
    return wrapping_key, aad


def wrap(
    *,
    sender_private_key: ec.EllipticCurvePrivateKey,
    recipient_public_key: ec.EllipticCurvePublicKey,
    snapshot_id: str,
    snapshot_key: bytes,
    aead_nonce: bytes,
) -> bytes:
    """Return ``nonce || ciphertext || tag`` for the v0.1 snapshot-key wrap."""
    _check_p256(sender_private_key, "sender_private_key")
    _check_p256(recipient_public_key, "recipient_public_key")
    if not isinstance(snapshot_key, (bytes, bytearray)):
        raise WrapError(reason=f"snapshot_key must be bytes, got {type(snapshot_key).__name__}")
    if len(snapshot_key) != _SNAPSHOT_KEY_LEN:
        raise WrapError(reason=f"snapshot_key must be {_SNAPSHOT_KEY_LEN} bytes, got {len(snapshot_key)}")
    if not isinstance(aead_nonce, (bytes, bytearray)):
        raise WrapError(reason=f"aead_nonce must be bytes, got {type(aead_nonce).__name__}")
    if len(aead_nonce) != _NONCE_LEN:
        raise WrapError(reason=f"aead_nonce must be {_NONCE_LEN} bytes, got {len(aead_nonce)}")

    wrapping_key, aad = _derive_wrapping_key(
        own_private_key=sender_private_key,
        peer_public_key=recipient_public_key,
        recipient_public_key=recipient_public_key,
        snapshot_id=snapshot_id,
    )
    ct_and_tag = _aead.encrypt(wrapping_key, bytes(aead_nonce), bytes(snapshot_key), aad)
    return bytes(aead_nonce) + ct_and_tag


def unwrap(
    *,
    recipient_private_key: ec.EllipticCurvePrivateKey,
    sender_public_key: ec.EllipticCurvePublicKey,
    snapshot_id: str,
    wrapped: bytes,
) -> bytes:
    """Recover the 32-byte snapshot key from a ``nonce || ciphertext || tag`` blob."""
    _check_p256(recipient_private_key, "recipient_private_key")
    _check_p256(sender_public_key, "sender_public_key")
    if not isinstance(wrapped, (bytes, bytearray)):
        raise WrapError(reason=f"wrapped must be bytes, got {type(wrapped).__name__}")
    if len(wrapped) < _NONCE_LEN + _TAG_LEN:
        raise WrapError(reason=f"wrapped shorter than nonce+tag: {len(wrapped)} bytes")

    nonce = bytes(wrapped[:_NONCE_LEN])
    ct_and_tag = bytes(wrapped[_NONCE_LEN:])

    wrapping_key, aad = _derive_wrapping_key(
        own_private_key=recipient_private_key,
        peer_public_key=sender_public_key,
        recipient_public_key=recipient_private_key.public_key(),
        snapshot_id=snapshot_id,
    )
    try:
        plaintext = _aead.decrypt(wrapping_key, nonce, ct_and_tag, aad)
    except Exception as exc:
        raise WrapError(reason="AEAD tag verification failed on unwrap") from exc
    if len(plaintext) != _SNAPSHOT_KEY_LEN:
        raise WrapError(reason=f"unwrapped key has wrong length: {len(plaintext)}")
    return plaintext
