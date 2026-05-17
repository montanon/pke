"""ECDH(P-256) + HKDF-SHA256 + AES-256-GCM snapshot-key wrap (algorithm id ``ecdhp256+aesgcm256``).

Implements the v0.1 snapshot-key wrap construction; the full byte layout for
HKDF salt/info and the AEAD AAD is locked in
``context/16_canonical_encoding.md`` (§"HKDF-SHA256 (snapshot key wrap)").
This is the only wrap algorithm at v0.1; cross-version negotiation is out of
scope for this primitive.

Construction summary
--------------------

1. ECDH on SECP256R1 between the owner private key and the recipient public
   key produces a 32-byte raw X-coordinate shared secret.
2. HKDF-SHA256 with the locked salt ``b"pke/v0.1/keywrap/salt"`` and an
   ``info`` of ``b"pke/v0.1/keywrap/info"`` followed by length-prefixed
   ``snapshot_id`` (UTF-8) and the recipient's 65-byte uncompressed
   ``0x04 || X || Y`` point derives a 32-byte AES key.
3. AES-256-GCM seals the 32-byte snapshot key with a 12-byte nonce and the
   locked AAD ``b"pke/v0.1/keywrap/aad"`` followed by the length-prefixed
   ``snapshot_id``.

Wire layout (60 bytes total): ``nonce(12) || ciphertext(32) || tag(16)``.

Errors
------

Structural problems (wrong types, wrong sizes, wrong curve) raise
``WrapError``. AEAD tag failure on unwrap (tamper, wrong recipient, wrong
``snapshot_id``, wrong owner public key) raises ``AEADError``.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pke_backend.crypto.errors import AEADError, WrapError
from pke_backend.crypto.kdf import hkdf_sha256

__all__ = ["unwrap_snapshot_key", "wrap_snapshot_key"]

_SNAPSHOT_KEY_LENGTH = 32
_NONCE_LENGTH = 12
_TAG_LENGTH = 16
_WRAPPED_LENGTH = _NONCE_LENGTH + _SNAPSHOT_KEY_LENGTH + _TAG_LENGTH  # 60
_UNCOMPRESSED_POINT_LENGTH = 65

_HKDF_SALT = b"pke/v0.1/keywrap/salt"
_HKDF_INFO_PREFIX = b"pke/v0.1/keywrap/info"
_AAD_PREFIX = b"pke/v0.1/keywrap/aad"


def _u16be(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _require_private_key(name: str, key: object) -> ec.EllipticCurvePrivateKey:
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise WrapError(reason=f"{name} must be EllipticCurvePrivateKey, got {type(key).__name__}")
    if not isinstance(key.curve, ec.SECP256R1):
        raise WrapError(reason=f"{name} must be on SECP256R1, got {key.curve.name}")
    return key


def _require_public_key(name: str, key: object) -> ec.EllipticCurvePublicKey:
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise WrapError(reason=f"{name} must be EllipticCurvePublicKey, got {type(key).__name__}")
    if not isinstance(key.curve, ec.SECP256R1):
        raise WrapError(reason=f"{name} must be on SECP256R1, got {key.curve.name}")
    return key


def _require_snapshot_id(snapshot_id: object) -> bytes:
    if not isinstance(snapshot_id, str):
        raise WrapError(reason=f"snapshot_id must be str, got {type(snapshot_id).__name__}")
    return snapshot_id.encode("utf-8")


def _recipient_uncompressed(recipient_public_key: ec.EllipticCurvePublicKey) -> bytes:
    raw = recipient_public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    if len(raw) != _UNCOMPRESSED_POINT_LENGTH or raw[0] != 0x04:
        # Defence in depth: pyca/cryptography always emits 65 bytes for P-256,
        # but the spec requires us to pin the exact wire shape we hash.
        raise WrapError(
            reason=(
                f"recipient public key serialization must be {_UNCOMPRESSED_POINT_LENGTH}-byte "
                f"uncompressed point, got {len(raw)} bytes"
            )
        )
    return raw


def _build_info(snapshot_id_bytes: bytes, recipient_pub_raw: bytes) -> bytes:
    return (
        _HKDF_INFO_PREFIX
        + _u16be(len(snapshot_id_bytes))
        + snapshot_id_bytes
        + _u16be(len(recipient_pub_raw))
        + recipient_pub_raw
    )


def _build_aad(snapshot_id_bytes: bytes) -> bytes:
    return _AAD_PREFIX + _u16be(len(snapshot_id_bytes)) + snapshot_id_bytes


def _derive_wrapping_key(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
    snapshot_id_bytes: bytes,
    recipient_pub_raw: bytes,
) -> bytes:
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    info = _build_info(snapshot_id_bytes, recipient_pub_raw)
    return hkdf_sha256(secret=shared, salt=_HKDF_SALT, info=info, length=_SNAPSHOT_KEY_LENGTH)


def wrap_snapshot_key(
    snapshot_key: bytes,
    owner_private_key: ec.EllipticCurvePrivateKey,
    recipient_public_key: ec.EllipticCurvePublicKey,
    snapshot_id: str,
    *,
    nonce: bytes | None = None,
) -> bytes:
    """Wrap a 32-byte snapshot key for ``recipient_public_key``.

    Returns the 60-byte ``nonce(12) || ciphertext(32) || tag(16)`` envelope.

    The ``nonce`` keyword is an additive escape hatch so vector tests can pin
    the AEAD nonce for determinism — production callers MUST omit it so a
    fresh ``os.urandom(12)`` nonce is generated per call. Reusing a nonce
    under the same wrapping key breaks AES-GCM confidentiality.
    """
    if not isinstance(snapshot_key, (bytes, bytearray)):
        raise WrapError(reason=f"snapshot_key must be bytes, got {type(snapshot_key).__name__}")
    if len(snapshot_key) != _SNAPSHOT_KEY_LENGTH:
        raise WrapError(reason=f"snapshot_key must be {_SNAPSHOT_KEY_LENGTH} bytes, got {len(snapshot_key)}")
    owner_priv = _require_private_key("owner_private_key", owner_private_key)
    recipient_pub = _require_public_key("recipient_public_key", recipient_public_key)
    snapshot_id_bytes = _require_snapshot_id(snapshot_id)

    if nonce is None:
        nonce_bytes = os.urandom(_NONCE_LENGTH)
    else:
        if not isinstance(nonce, (bytes, bytearray)):
            raise WrapError(reason=f"nonce must be bytes, got {type(nonce).__name__}")
        if len(nonce) != _NONCE_LENGTH:
            raise WrapError(reason=f"nonce must be {_NONCE_LENGTH} bytes, got {len(nonce)}")
        nonce_bytes = bytes(nonce)

    recipient_pub_raw = _recipient_uncompressed(recipient_pub)
    wrapping_key = _derive_wrapping_key(owner_priv, recipient_pub, snapshot_id_bytes, recipient_pub_raw)
    aad = _build_aad(snapshot_id_bytes)
    aesgcm = AESGCM(wrapping_key)
    sealed = aesgcm.encrypt(nonce_bytes, bytes(snapshot_key), aad)
    return nonce_bytes + sealed


def unwrap_snapshot_key(
    wrapped: bytes,
    recipient_private_key: ec.EllipticCurvePrivateKey,
    owner_public_key: ec.EllipticCurvePublicKey,
    snapshot_id: str,
) -> bytes:
    """Unwrap a 60-byte envelope produced by :func:`wrap_snapshot_key`.

    Raises ``WrapError`` for structural problems and ``AEADError`` when the
    GCM tag fails (tamper, wrong ``snapshot_id``, wrong key material).
    """
    if not isinstance(wrapped, (bytes, bytearray)):
        raise WrapError(reason=f"wrapped must be bytes, got {type(wrapped).__name__}")
    if len(wrapped) != _WRAPPED_LENGTH:
        raise WrapError(reason=f"wrapped must be {_WRAPPED_LENGTH} bytes, got {len(wrapped)}")
    recipient_priv = _require_private_key("recipient_private_key", recipient_private_key)
    owner_pub = _require_public_key("owner_public_key", owner_public_key)
    snapshot_id_bytes = _require_snapshot_id(snapshot_id)

    wrapped_bytes = bytes(wrapped)
    nonce = wrapped_bytes[:_NONCE_LENGTH]
    ciphertext_and_tag = wrapped_bytes[_NONCE_LENGTH:]

    # HKDF info pins the recipient's own public key — derive it from the
    # private key, never from the supplied owner_pub which is the peer.
    recipient_pub_raw = _recipient_uncompressed(recipient_priv.public_key())
    wrapping_key = _derive_wrapping_key(recipient_priv, owner_pub, snapshot_id_bytes, recipient_pub_raw)
    aad = _build_aad(snapshot_id_bytes)
    aesgcm = AESGCM(wrapping_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise AEADError(reason="snapshot key unwrap failed AEAD tag verification") from exc
    return plaintext
