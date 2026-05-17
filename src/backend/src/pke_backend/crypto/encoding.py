"""Base64url and hex encoding helpers. Tentative surface."""

from __future__ import annotations

__all__ = ["b64url_decode", "b64url_encode", "hex_decode", "hex_encode"]


def b64url_encode(data: bytes) -> str:
    raise NotImplementedError


def b64url_decode(s: str) -> bytes:
    raise NotImplementedError


def hex_encode(data: bytes) -> str:
    raise NotImplementedError


def hex_decode(s: str) -> bytes:
    raise NotImplementedError
