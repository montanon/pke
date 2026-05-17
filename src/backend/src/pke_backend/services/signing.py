"""Signing helpers — canonical-body extraction, pubkey load, signature verify.

Bridges the protocol Pydantic models (``ReportAction``, ``FreezeAction``, and
future siblings) to the strict crypto primitives in
:mod:`pke_backend.crypto.signatures` so endpoint code never reaches into the
low-level verifier directly.

The "signed body" rule from ``context/16_canonical_encoding.md`` is implemented
once here:

    ``signed_body = canonical_json(full_payload minus the *_signature field)``

The exact name of the signature field varies by payload type (``report_signature``,
``freeze_signature``, etc.), so callers pass it explicitly.

Errors raised:

* :class:`pke_backend.crypto.errors.SignatureFormatError` — wrong key length /
  curve, wrong signature length, bytes-typing mismatch. Raised eagerly before
  any verify math runs.
* :class:`pke_backend.crypto.errors.SignatureVerificationError` — well-formed
  inputs whose math does not validate.

The API layer (:mod:`pke_backend.api.errors`) maps both to ``401
signature_invalid`` so endpoint handlers do not catch these directly.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.errors import SignatureFormatError
from pke_backend.crypto.signatures import verify_signature
from pke_backend.protocol.types import ToJsonValueMixin

__all__ = ["canonical_signed_body", "load_p256_public_key", "verify_action_signature"]


def canonical_signed_body(action: ToJsonValueMixin, signature_field: str) -> bytes:
    """Return the canonical JSON bytes of ``action`` with ``signature_field`` removed.

    The result is exactly what the signing device hashed under
    ECDSA-P256-SHA256, so it can be re-fed to :func:`verify_signature` or to a
    SHA-256 ledger ``payload_hash`` computation.
    """
    body = action.to_json_value()
    if not isinstance(body, dict):
        # ``to_json_value`` on a Pydantic model always returns a dict; this
        # branch is defensive against future protocol additions.
        raise SignatureFormatError(reason="action payload is not a JSON object")
    # ``dict.pop`` with a default avoids surprising errors when called against a
    # model that omits the signature field (e.g. partial test fixtures); the
    # caller's intent is "drop this field if present".
    body.pop(signature_field, None)
    return canonicalize(body)


def load_p256_public_key(raw: bytes) -> ec.EllipticCurvePublicKey:
    """Parse a 65-byte uncompressed P-256 public key (``0x04 || X || Y``).

    Any structural failure surfaces as :class:`SignatureFormatError` so callers
    can rely on a single error taxonomy for "this key is not usable".
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise SignatureFormatError(reason=f"public key must be bytes, got {type(raw).__name__}")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(raw))
    except ValueError as exc:
        raise SignatureFormatError(reason="public key parse failed") from exc


def verify_action_signature(
    action: ToJsonValueMixin,
    *,
    signature_field: str,
    public_key_field: str,
) -> None:
    """Verify the ``*_signature`` on ``action`` using its embedded public key.

    Reads the public key (raw bytes) and signature (raw bytes) from the named
    attributes of ``action``, parses the key, reconstructs the canonical signed
    body (excluding ``signature_field``), and calls
    :func:`pke_backend.crypto.signatures.verify_signature`.

    Returns ``None`` on success; raises ``SignatureFormatError`` or
    ``SignatureVerificationError`` otherwise.
    """
    public_key_bytes = getattr(action, public_key_field)
    signature_bytes = getattr(action, signature_field)
    public_key = load_p256_public_key(public_key_bytes)
    body = canonical_signed_body(action, signature_field)
    verify_signature(public_key, body, signature_bytes)
