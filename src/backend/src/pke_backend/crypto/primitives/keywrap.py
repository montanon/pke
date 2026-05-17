"""ECDH-P256 + HKDF + AES-GCM key wrap primitive. Tentative surface.

See `context/04_protocol_overview.md` §Wrapping algorithm guidance.
"""

from __future__ import annotations

__all__ = ["unwrap", "wrap"]


def wrap(
    recipient_public_key: object,
    sender_private_key: object,
    key: bytes,
) -> bytes:
    raise NotImplementedError


def unwrap(
    sender_public_key: object,
    recipient_private_key: object,
    wrapped: bytes,
) -> bytes:
    raise NotImplementedError
