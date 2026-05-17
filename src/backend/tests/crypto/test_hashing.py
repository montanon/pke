from __future__ import annotations

import json
from pathlib import Path

import pytest

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import HashChainError
from pke_backend.crypto.hashing import sha256, verify_hash_chain
from pke_backend.crypto.types import JsonValue

SHA256_VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "sha256"

GENESIS_PREVIOUS_ENTRY_HASH_B64 = b64url_encode(b"\x00" * 32)
DUMMY_PAYLOAD_HASH_B64 = b64url_encode(sha256(b"payload"))


def make_entry(
    *,
    previous_entry_hash_b64: str,
    payload_hash_b64: str = DUMMY_PAYLOAD_HASH_B64,
    idx: int = 0,
) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "type": "ledger_entry",
        "version": "v0.1",
        "ledger_entry_id": f"entry-{idx}",
        "event_type": "SNAPSHOT_COMMITTED",
        "snapshot_id": "snap-1",
        "payload_hash": payload_hash_b64,
        "previous_entry_hash": previous_entry_hash_b64,
        "entry_timestamp": "2026-05-15T00:00:00Z",
    }
    entry_hash = sha256(canonicalize(body))
    return {**body, "entry_hash": b64url_encode(entry_hash)}


def make_chain(length: int) -> list[dict[str, JsonValue]]:
    chain: list[dict[str, JsonValue]] = []
    previous_b64 = GENESIS_PREVIOUS_ENTRY_HASH_B64
    for idx in range(length):
        entry = make_entry(previous_entry_hash_b64=previous_b64, idx=idx)
        chain.append(entry)
        # The next entry's previous_entry_hash is this entry's entry_hash.
        entry_hash_value = entry["entry_hash"]
        assert isinstance(entry_hash_value, str)
        previous_b64 = entry_hash_value
    return chain


def test_sha256_empty_input() -> None:
    assert sha256(b"") == bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # pragma: allowlist secret
    )


def test_sha256_abc() -> None:
    assert sha256(b"abc") == bytes.fromhex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",  # pragma: allowlist secret
    )


def test_sha256_returns_thirty_two_bytes() -> None:
    digest = sha256(b"some bytes")
    assert isinstance(digest, bytes)
    assert len(digest) == 32


def test_verify_hash_chain_empty_returns_none() -> None:
    # No exception, no return value (implicit None).
    verify_hash_chain([])


def test_verify_hash_chain_single_genesis_entry() -> None:
    chain = make_chain(1)
    verify_hash_chain(chain)


def test_verify_hash_chain_two_entry_valid_chain() -> None:
    chain = make_chain(2)
    verify_hash_chain(chain)


def test_verify_hash_chain_longer_valid_chain() -> None:
    chain = make_chain(5)
    verify_hash_chain(chain)


def test_verify_hash_chain_mutated_entry_hash() -> None:
    chain = make_chain(2)
    # Flip the first character of the second entry's entry_hash so the
    # decoded bytes no longer match SHA256(body).
    original = chain[1]["entry_hash"]
    assert isinstance(original, str)
    mutated = ("A" if original[0] != "A" else "B") + original[1:]
    chain[1]["entry_hash"] = mutated
    with pytest.raises(HashChainError):
        verify_hash_chain(chain)


def test_verify_hash_chain_first_entry_not_genesis() -> None:
    not_genesis = b64url_encode(b"\x01" * 32)
    entry = make_entry(previous_entry_hash_b64=not_genesis, idx=0)
    with pytest.raises(HashChainError):
        verify_hash_chain([entry])


def test_verify_hash_chain_chain_break() -> None:
    chain = make_chain(2)
    # Replace second entry's previous_entry_hash with the genesis value
    # so it no longer matches entry[0].entry_hash. Rebuild entry_hash so the
    # mismatch surfaces as a chain break and not an entry_hash mismatch.
    body = {k: v for k, v in chain[1].items() if k != "entry_hash"}
    body["previous_entry_hash"] = GENESIS_PREVIOUS_ENTRY_HASH_B64
    rebuilt: dict[str, JsonValue] = {
        **body,
        "entry_hash": b64url_encode(sha256(canonicalize(body))),
    }
    chain[1] = rebuilt
    with pytest.raises(HashChainError):
        verify_hash_chain(chain)


def test_verify_hash_chain_missing_entry_hash() -> None:
    entry = make_entry(previous_entry_hash_b64=GENESIS_PREVIOUS_ENTRY_HASH_B64)
    del entry["entry_hash"]
    with pytest.raises(HashChainError):
        verify_hash_chain([entry])


def test_verify_hash_chain_missing_previous_entry_hash() -> None:
    entry = make_entry(previous_entry_hash_b64=GENESIS_PREVIOUS_ENTRY_HASH_B64)
    del entry["previous_entry_hash"]
    with pytest.raises(HashChainError):
        verify_hash_chain([entry])


def test_verify_hash_chain_malformed_entry_hash_padded() -> None:
    entry = make_entry(previous_entry_hash_b64=GENESIS_PREVIOUS_ENTRY_HASH_B64)
    current = entry["entry_hash"]
    assert isinstance(current, str)
    entry["entry_hash"] = current + "=="  # padding is rejected by b64url_decode
    with pytest.raises(HashChainError):
        verify_hash_chain([entry])


def test_verify_hash_chain_entry_hash_wrong_length() -> None:
    entry = make_entry(previous_entry_hash_b64=GENESIS_PREVIOUS_ENTRY_HASH_B64)
    # 16 zero bytes encoded as base64url is the wrong digest length.
    entry["entry_hash"] = b64url_encode(b"\x00" * 16)
    with pytest.raises(HashChainError):
        verify_hash_chain([entry])


def test_verify_hash_chain_entry_hash_non_string() -> None:
    entry = make_entry(previous_entry_hash_b64=GENESIS_PREVIOUS_ENTRY_HASH_B64)
    entry["entry_hash"] = 42
    with pytest.raises(HashChainError):
        verify_hash_chain([entry])


def _load_sha256_vector(name: str) -> dict[str, object]:
    return json.loads((SHA256_VECTORS_DIR / name).read_text())


def _sha256_vectors(prefix: str) -> list[str]:
    return sorted(p.name for p in SHA256_VECTORS_DIR.glob(f"{prefix}*.json"))


SHA256_POSITIVE_VECTORS = _sha256_vectors("p")
SHA256_NEGATIVE_VECTORS = _sha256_vectors("n")


def test_sha256_vector_directory_populated() -> None:
    assert SHA256_POSITIVE_VECTORS, "expected positive sha256 vectors"
    assert SHA256_NEGATIVE_VECTORS, "expected the negative sha256 vector"


@pytest.mark.parametrize("vector", SHA256_POSITIVE_VECTORS)
def test_sha256_positive_vector_digest_matches(vector: str) -> None:
    bundle = _load_sha256_vector(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    message = bytes.fromhex(str(inputs["message_hex"]))
    assert sha256(message).hex() == expected["digest_hex"]


@pytest.mark.parametrize("vector", SHA256_NEGATIVE_VECTORS)
def test_sha256_negative_vector_digest_diverges(vector: str) -> None:
    bundle = _load_sha256_vector(vector)
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    message = bytes.fromhex(str(inputs["message_hex"]))
    # sha256 is total; the documented failure for a corrupted digest is a
    # byte-mismatch rather than an exception path.
    assert sha256(message).hex() != expected["digest_hex"]
