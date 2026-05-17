"""ECDSA P-256 signature verification with strict raw P1363 inputs.

The protocol pins ECDSA over P-256 with SHA-256 and a raw P1363 wire format
(exactly 64 bytes: `r || s`, each big-endian, left-padded to 32 bytes). DER
inputs and any other length must be rejected at this boundary — see
`context/16_canonical_encoding.md` (ECDSA section).

pyca/cryptography only accepts DER-encoded signatures through
`EllipticCurvePublicKey.verify`, so the wrapper:

1. Validates the wire length is exactly 64 bytes,
2. Splits into `(r, s)` and re-encodes via `encode_dss_signature` to feed
   the underlying primitive,
3. Maps `InvalidSignature` to `SignatureVerificationError` and any
   structural problem (length, type) to `SignatureFormatError` *before*
   the verify math runs.

`sign_payload` remains a stub: the backend is a verifier in this story and
does not produce signatures.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from pke_backend.crypto.errors import SignatureFormatError, SignatureVerificationError

__all__ = ["sign_payload", "verify_payload", "verify_signature"]

_P1363_LENGTH = 64
_COORD_LENGTH = 32


def verify_signature(
    public_key: ec.EllipticCurvePublicKey,
    payload: bytes,
    sig: bytes,
) -> None:
    """Verify a raw P1363 ECDSA-P256-SHA256 signature over ``payload``.

    Returns ``None`` on success. Raises ``SignatureFormatError`` for any
    structural problem (wrong type, wrong length) before any verification
    math runs. Raises ``SignatureVerificationError`` when the signature is
    well-formed but does not validate.
    """
    if not isinstance(sig, (bytes, bytearray)):
        raise SignatureFormatError(reason=f"signature must be bytes, got {type(sig).__name__}")
    if len(sig) != _P1363_LENGTH:
        raise SignatureFormatError(reason=f"expected {_P1363_LENGTH}-byte raw P1363 signature, got {len(sig)} bytes")
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise SignatureFormatError(reason=f"public_key must be EllipticCurvePublicKey, got {type(public_key).__name__}")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise SignatureFormatError(reason=f"expected P-256 key, got curve {public_key.curve.name}")
    if not isinstance(payload, (bytes, bytearray)):
        raise SignatureFormatError(reason=f"payload must be bytes, got {type(payload).__name__}")

    r = int.from_bytes(bytes(sig[:_COORD_LENGTH]), "big")
    s = int.from_bytes(bytes(sig[_COORD_LENGTH:]), "big")
    der = encode_dss_signature(r, s)
    try:
        public_key.verify(der, bytes(payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise SignatureVerificationError(reason="signature did not validate") from exc


def sign_payload(canonical: bytes, private_key: object) -> bytes:
    raise NotImplementedError


def verify_payload(canonical: bytes, signature: bytes, public_key: object) -> None:
    raise NotImplementedError
