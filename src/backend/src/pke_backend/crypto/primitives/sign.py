"""ECDSA P-256 raw P1363 signing primitive — fixture/test-only.

The protocol pins ECDSA over P-256 with SHA-256 and a raw P1363 wire format
(exactly 64 bytes: `r || s`, each big-endian, left-padded to 32 bytes). See
`context/16_canonical_encoding.md` (ECDSA section).

The backend itself is a verifier (see ``pke_backend.crypto.signatures``);
this primitive exists solely to produce wire-format signatures for tests
and fixtures. It is the inverse of ``verify_signature``: a signature
produced here must verify against the matching public key.

pyca/cryptography only emits DER-encoded signatures through
``EllipticCurvePrivateKey.sign``, so the wrapper:

1. Validates ``payload`` is bytes and ``private_key`` is a P-256
   ``EllipticCurvePrivateKey`` *before* any signing math runs,
2. Signs to DER, then decodes via ``decode_dss_signature`` and re-encodes
   ``(r, s)`` as fixed-width 32-byte big-endian halves.

Errors map to ``SignatureFormatError`` with reasons that never reference
key material.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pke_backend.crypto.errors import SignatureFormatError

__all__ = ["sign"]

_COORD_LENGTH = 32


def sign(payload: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Sign ``payload`` with ECDSA-P256-SHA256, returning a 64-byte raw P1363 signature.

    Returns ``r || s`` (each 32 bytes, big-endian, left-padded). Raises
    ``SignatureFormatError`` for any structural problem (wrong payload
    type, wrong key type, non-P256 curve) before any signing math runs.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise SignatureFormatError(reason=f"payload must be bytes, got {type(payload).__name__}")
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise SignatureFormatError(
            reason=f"private_key must be EllipticCurvePrivateKey, got {type(private_key).__name__}"
        )
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise SignatureFormatError(reason=f"expected P-256 key, got curve {private_key.curve.name}")

    der = private_key.sign(bytes(payload), ec.ECDSA(hashes.SHA256()))
    r_int, s_int = decode_dss_signature(der)
    r: int = r_int
    s: int = s_int
    return r.to_bytes(_COORD_LENGTH, "big") + s.to_bytes(_COORD_LENGTH, "big")
