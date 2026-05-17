"""ECDSA P-256 signing primitive. Tentative surface."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

__all__ = ["generate_keypair", "sign", "verify"]

# Curve pinned for the downstream P-256 ECDSA implementation; also keeps the
# `ec` import live for AC #2 (the import must resolve in this Story).
_CURVE = ec.SECP256R1


def generate_keypair() -> tuple[object, object]:
    raise NotImplementedError


def sign(private_key: object, message: bytes) -> bytes:
    raise NotImplementedError


def verify(public_key: object, message: bytes, signature: bytes) -> None:
    raise NotImplementedError
