"""Crypto package — protocol-aligned helpers and primitives for PKE backend.

Surfaces declared here are stable imports for downstream HLAM-5 stories.
"""

from __future__ import annotations

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import (
    b64url_decode,
    b64url_encode,
    hex_decode,
    hex_encode,
)
from pke_backend.crypto.errors import (
    AEADError,
    CanonicalEncodingError,
    CryptoError,
    EncodingError,
    HashChainError,
    SignatureFormatError,
    SignatureVerificationError,
    WrapError,
)
from pke_backend.crypto.hashing import sha256, verify_hash_chain
from pke_backend.crypto.types import JsonValue

__all__ = [
    "AEADError",
    "CanonicalEncodingError",
    "CryptoError",
    "EncodingError",
    "HashChainError",
    "JsonValue",
    "SignatureFormatError",
    "SignatureVerificationError",
    "WrapError",
    "b64url_decode",
    "b64url_encode",
    "canonicalize",
    "hex_decode",
    "hex_encode",
    "sha256",
    "verify_hash_chain",
]
