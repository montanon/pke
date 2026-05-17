"""SHA-256 hashing and ledger hash-chain extension. Tentative surface."""

from __future__ import annotations

__all__ = ["hash_chain", "sha256"]


def sha256(data: bytes) -> bytes:
    raise NotImplementedError


def hash_chain(previous_hash: bytes, payload_hash: bytes) -> bytes:
    raise NotImplementedError
