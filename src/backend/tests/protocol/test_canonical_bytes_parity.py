from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from pke_backend.crypto import canonicalize
from pke_backend.protocol import (
    KeyGrant,
    LedgerEntry,
    SnapshotCommitment,
    VerificationReport,
    WitnessAttestation,
)

EXAMPLES_DIR = Path(__file__).resolve().parents[4] / "context" / "examples"

# One entry per protocol payload model — the bytes fixture is the byte-exact
# output of `canonicalize(model.to_json_value())`, not raw canonicalize of
# the source example, since `Base64UrlBytes` round-tripping rewrites
# placeholder strings to their strict canonical form.
PAYLOAD_MODELS: dict[str, type[BaseModel]] = {
    "snapshot_commitment": SnapshotCommitment,
    "witness_attestation": WitnessAttestation,
    "ledger_entry": LedgerEntry,
    "key_grant": KeyGrant,
    "verification_report": VerificationReport,
}


def _example_path(name: str) -> Path:
    return EXAMPLES_DIR / f"{name}.example.json"


def _fixture_path(name: str) -> Path:
    return EXAMPLES_DIR / f"{name}.canonical-bytes"


@pytest.mark.parametrize(("name", "model"), list(PAYLOAD_MODELS.items()))
def test_model_round_trip_matches_canonical_bytes(name: str, model: type[BaseModel]) -> None:
    source = json.loads(_example_path(name).read_text())
    fixture = _fixture_path(name).read_bytes()
    instance = model.model_validate(source)
    actual = canonicalize(instance.to_json_value())
    assert actual == fixture, (
        f"canonical-bytes drift for {name}:\n"
        f"--- fixture ({len(fixture)} bytes) ---\n{fixture!r}\n"
        f"--- pydantic round-trip ({len(actual)} bytes) ---\n{actual!r}"
    )


def test_every_payload_model_has_example_and_fixture() -> None:
    missing = [name for name in PAYLOAD_MODELS if not _example_path(name).exists() or not _fixture_path(name).exists()]
    assert not missing, f"protocol payloads without an example or canonical-bytes fixture: {missing}"
