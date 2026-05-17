"""SHA-256 helper and ledger hash-chain verification.

See `context/16_canonical_encoding.md` section "Hash chain". Locked at v0.1:

* `entry_body = canonical_json(ledger_entry minus the entry_hash field)`
* `entry_hash = SHA256(entry_body)`; the raw 32 bytes are base64url-no-pad
  encoded into the wire-level `entry_hash` field.
* `previous_entry_hash` is the base64url-no-pad encoding of either the prior
  entry's raw 32-byte `entry_hash` or, for the genesis entry, of 32 zero
  bytes.

`verify_hash_chain` enforces these invariants. Error `reason` strings reference
only positional indices and lengths so verification failures never leak
content bytes.
"""

from __future__ import annotations

import hashlib

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_decode
from pke_backend.crypto.errors import (
    CanonicalEncodingError,
    EncodingError,
    HashChainError,
)
from pke_backend.crypto.types import JsonValue

__all__ = ["sha256", "verify_hash_chain"]

_GENESIS_PREVIOUS_ENTRY_HASH = b"\x00" * 32
_DIGEST_LEN = 32


def sha256(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of `data`."""
    return hashlib.sha256(data).digest()


def _decode_chain_field(
    value: JsonValue,
    *,
    field: str,
    index: int,
) -> bytes:
    if not isinstance(value, str):
        raise HashChainError(
            reason=f"{field} at index {index} must be a string",
        )
    try:
        decoded = b64url_decode(value)
    except EncodingError as exc:
        raise HashChainError(
            reason=f"{field} at index {index} is not valid base64url",
        ) from exc
    if len(decoded) != _DIGEST_LEN:
        raise HashChainError(
            reason=(f"{field} at index {index} decoded to {len(decoded)} bytes; expected {_DIGEST_LEN}"),
        )
    return decoded


def verify_hash_chain(entries: list[dict[str, JsonValue]]) -> None:
    """Verify the integrity of an append-only ledger hash chain.

    The empty chain is treated as trivially valid (no work to do).

    For each entry the verifier:

    1. Decodes `entry_hash` (must be 32 bytes after base64url-no-pad decode).
    2. Canonicalizes the entry with `entry_hash` removed and recomputes the
       SHA-256 digest.
    3. Compares the decoded `entry_hash` to the recomputed digest.
    4. For the genesis entry (`i == 0`) confirms `previous_entry_hash`
       decodes to 32 zero bytes.
    5. For every subsequent entry confirms `previous_entry_hash` equals the
       prior entry's decoded `entry_hash` byte-for-byte.

    Raises:
        HashChainError: if any of the invariants above fails. The `reason`
            payload only references indices and lengths — never content bytes.

    """
    if not entries:
        return

    prior_entry_hash: bytes | None = None
    for index, entry in enumerate(entries):
        if "entry_hash" not in entry:
            raise HashChainError(reason=f"missing entry_hash at index {index}")
        if "previous_entry_hash" not in entry:
            raise HashChainError(
                reason=f"missing previous_entry_hash at index {index}",
            )

        entry_hash_bytes = _decode_chain_field(
            entry["entry_hash"],
            field="entry_hash",
            index=index,
        )

        body_value: dict[str, JsonValue] = {k: v for k, v in entry.items() if k != "entry_hash"}
        try:
            body = canonicalize(body_value)
        except CanonicalEncodingError as exc:
            raise HashChainError(
                reason=f"failed to canonicalize entry body at index {index}",
            ) from exc

        if sha256(body) != entry_hash_bytes:
            raise HashChainError(
                reason=f"entry_hash mismatch at index {index}",
            )

        previous_bytes = _decode_chain_field(
            entry["previous_entry_hash"],
            field="previous_entry_hash",
            index=index,
        )

        if index == 0:
            if previous_bytes != _GENESIS_PREVIOUS_ENTRY_HASH:
                raise HashChainError(
                    reason="genesis previous_entry_hash must be 32 zero bytes",
                )
        else:
            assert prior_entry_hash is not None
            if previous_bytes != prior_entry_hash:
                raise HashChainError(
                    reason=f"chain break at index {index}",
                )

        prior_entry_hash = entry_hash_bytes
