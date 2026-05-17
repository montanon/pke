"""Deterministic canonical encoding for signed payloads.

See `context/04_protocol_overview.md` §Canonical payloads. Tentative surface; downstream
stories may refine.
"""

from __future__ import annotations

from pke_backend.crypto.types import JsonValue

__all__ = ["canonicalize"]


def canonicalize(value: JsonValue) -> bytes:
    raise NotImplementedError
