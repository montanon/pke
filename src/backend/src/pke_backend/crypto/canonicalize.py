"""Deterministic canonical encoding for signed payloads.

See `context/16_canonical_encoding.md` §Canonical JSON. Rules locked at v0.1:
keys sorted by UTF-8 byte sequence at every level, minified separators,
UTF-8 output without `\\uXXXX` escapes, no trailing newline, NaN/Infinity
rejected, recursion depth bounded.
"""

from __future__ import annotations

import json

from pke_backend.crypto.errors import CanonicalEncodingError
from pke_backend.crypto.types import JsonValue

__all__ = ["canonicalize"]

MAX_DEPTH = 64


def _check_depth(value: JsonValue, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalEncodingError(f"nesting exceeds MAX_DEPTH={MAX_DEPTH}")
    if isinstance(value, dict):
        for v in value.values():
            _check_depth(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            _check_depth(v, depth + 1)


def canonicalize(value: JsonValue) -> bytes:
    _check_depth(value, 1)
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalEncodingError(f"json.dumps failed: {type(exc).__name__}") from exc
    return encoded.encode("utf-8")
