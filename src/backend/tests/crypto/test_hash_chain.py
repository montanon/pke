"""Parity tests for the ledger hash-chain construction against
``src/shared/test_vectors/hash_chain/*.json``.

Each vector pins a sequence of entry bodies under the construction
``entry_hash[i] = SHA256(canonical_json(entry_i))``, where ``entry_i``
includes ``previous_entry_hash_hex`` (the prior entry's hash, or 32 zero bytes
for genesis).

Positive vectors assert byte-identical recomputed hashes and well-formed
linkage. The negative vector pins ``broken_at_index`` and asserts the
recomputed hashes diverge from the recorded baseline at that index — the
divergence is the documented failure signal for the parity contract. The
exception-path (``HashChainError``) is exercised separately in
``test_hashing.py`` against the production wire-shape verifier.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.types import JsonValue

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "hash_chain"

_GENESIS_PREV = "00" * 32


def _load(name: str) -> dict[str, object]:
    return json.loads((VECTORS_DIR / name).read_text())


def _vectors(prefix: str) -> list[str]:
    return sorted(p.name for p in VECTORS_DIR.glob(f"{prefix}*.json"))


def _recompute_entry_hashes(chain: list[dict[str, JsonValue]]) -> list[str]:
    return [sha256(canonicalize(entry)).hex() for entry in chain]


POSITIVE_VECTORS = _vectors("p")
NEGATIVE_VECTORS = _vectors("n")


def test_vector_directory_populated() -> None:
    assert POSITIVE_VECTORS, "expected at least one positive hash-chain vector"
    assert NEGATIVE_VECTORS, "expected the negative hash-chain vector"


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_positive_vector_entry_hashes_match(vector: str) -> None:
    bundle = _load(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    chain = inputs["chain"]
    assert isinstance(chain, list)
    assert _recompute_entry_hashes(chain) == expected["entry_hashes_hex"]


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_positive_vector_chain_linkage_holds(vector: str) -> None:
    bundle = _load(vector)
    inputs = bundle["inputs"]
    chain = inputs["chain"]
    assert isinstance(chain, list)
    hashes = _recompute_entry_hashes(chain)
    for i, entry in enumerate(chain):
        prev = str(entry["previous_entry_hash_hex"])
        if i == 0:
            assert prev == _GENESIS_PREV
        else:
            assert prev == hashes[i - 1]


@pytest.mark.parametrize("vector", NEGATIVE_VECTORS)
def test_negative_vector_diverges_at_broken_index(vector: str) -> None:
    bundle = _load(vector)
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)

    chain = inputs["chain"]
    assert isinstance(chain, list)
    recorded = expected["entry_hashes_hex"]
    assert isinstance(recorded, list)
    broken_at = int(expected["broken_at_index"])  # type: ignore[arg-type]

    recomputed = _recompute_entry_hashes(chain)
    assert recomputed[:broken_at] == recorded[:broken_at]
    assert recomputed[broken_at] != recorded[broken_at]
