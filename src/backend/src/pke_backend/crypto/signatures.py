"""High-level payload signing and verification. Tentative surface.

Key parameters are typed as `object` here; a typed Protocol can land in a follow-up story.
"""

from __future__ import annotations

__all__ = ["sign_payload", "verify_payload"]


def sign_payload(canonical: bytes, private_key: object) -> bytes:
    raise NotImplementedError


def verify_payload(canonical: bytes, signature: bytes, public_key: object) -> None:
    raise NotImplementedError
