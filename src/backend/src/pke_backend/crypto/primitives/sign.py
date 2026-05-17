"""ECDSA P-256 signing primitive (test-only).

Emits/consumes raw P1363 64-byte signatures per ``context/16_canonical_encoding.md``
§ECDSA. Production code uses ``pke_backend.crypto.signatures.verify_signature``;
this module exists so fixture-builders and tests can produce signatures
deterministically.

Import is restricted to ``src/backend/tests/**`` and ``src/shared/tools/**``
by the ruff banned-api rule and the AST boundary test.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from pke_backend.crypto.errors import SignatureFormatError, SignatureVerificationError

__all__ = ["generate_keypair", "sign", "verify"]

_CURVE = ec.SECP256R1
_P1363_LENGTH = 64
_COORD_LENGTH = 32


def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Return a fresh (private, public) P-256 keypair."""
    priv = ec.generate_private_key(_CURVE())
    return priv, priv.public_key()


def sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign ``message`` with ECDSA-P256-SHA256 and return a raw P1363 (64-byte) signature."""
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise SignatureFormatError(
            reason=f"private_key must be EllipticCurvePrivateKey, got {type(private_key).__name__}"
        )
    if not isinstance(private_key.curve, _CURVE):
        raise SignatureFormatError(reason=f"expected P-256 key, got curve {private_key.curve.name}")
    if not isinstance(message, (bytes, bytearray)):
        raise SignatureFormatError(reason=f"message must be bytes, got {type(message).__name__}")
    der = private_key.sign(bytes(message), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(_COORD_LENGTH, "big") + s.to_bytes(_COORD_LENGTH, "big")


def verify(public_key: ec.EllipticCurvePublicKey, message: bytes, signature: bytes) -> None:
    """Verify a raw P1363 ECDSA-P256-SHA256 signature. Raises on any failure."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise SignatureFormatError(reason=f"public_key must be EllipticCurvePublicKey, got {type(public_key).__name__}")
    if not isinstance(public_key.curve, _CURVE):
        raise SignatureFormatError(reason=f"expected P-256 key, got curve {public_key.curve.name}")
    if not isinstance(message, (bytes, bytearray)):
        raise SignatureFormatError(reason=f"message must be bytes, got {type(message).__name__}")
    if not isinstance(signature, (bytes, bytearray)):
        raise SignatureFormatError(reason=f"signature must be bytes, got {type(signature).__name__}")
    if len(signature) != _P1363_LENGTH:
        raise SignatureFormatError(
            reason=f"expected {_P1363_LENGTH}-byte raw P1363 signature, got {len(signature)} bytes"
        )
    r = int.from_bytes(bytes(signature[:_COORD_LENGTH]), "big")
    s = int.from_bytes(bytes(signature[_COORD_LENGTH:]), "big")
    der = encode_dss_signature(r, s)
    try:
        public_key.verify(der, bytes(message), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise SignatureVerificationError(reason="signature did not validate") from exc
