"""Test-only primitive operations (sign, AEAD seal/open, ECDH key wrap).

These symbols are dangerous in production code paths and exist solely to
support the cross-language vector generator and the interop test suite.
The import-boundary story enforces that nothing outside ``tests/**`` or
``src/shared/tools/**`` may import this subpackage.
"""

from __future__ import annotations

from pke_backend.crypto.primitives.aead import aead_open, aead_seal
from pke_backend.crypto.primitives.keywrap import unwrap_snapshot_key, wrap_snapshot_key
from pke_backend.crypto.primitives.sign import sign

__all__ = [
    "aead_open",
    "aead_seal",
    "sign",
    "unwrap_snapshot_key",
    "wrap_snapshot_key",
]
