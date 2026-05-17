from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.protocol import (
    KeyGrant,
    LedgerEntry,
    LedgerEventType,
    SnapshotCommitment,
    VerificationReport,
    WitnessAttestation,
)

EXAMPLES_DIR = Path(__file__).resolve().parents[4] / "context" / "examples"


def _load(name: str) -> dict[str, Any]:
    path = EXAMPLES_DIR / name
    with path.open(encoding="utf-8") as f:
        loaded = json.load(f)
    assert isinstance(loaded, dict)
    return loaded


MODEL_FIXTURES: list[tuple[type[BaseModel], str]] = [
    (SnapshotCommitment, "snapshot_commitment.example.json"),
    (WitnessAttestation, "witness_attestation.example.json"),
    (LedgerEntry, "ledger_entry.example.json"),
    (KeyGrant, "key_grant.example.json"),
    (VerificationReport, "verification_report.example.json"),
]


@pytest.mark.parametrize(("model_cls", "fixture"), MODEL_FIXTURES)
def test_model_validates_example_fixture(model_cls: type[BaseModel], fixture: str) -> None:
    data = _load(fixture)
    instance = model_cls.model_validate(data)
    assert isinstance(instance, model_cls)


@pytest.mark.parametrize(("model_cls", "fixture"), MODEL_FIXTURES)
def test_model_rejects_unknown_field(model_cls: type[BaseModel], fixture: str) -> None:
    data = _load(fixture)
    data["__unexpected__"] = "x"
    with pytest.raises(ValidationError):
        model_cls.model_validate(data)


@pytest.mark.parametrize(("model_cls", "fixture"), MODEL_FIXTURES)
def test_canonicalize_round_trip(model_cls: type[BaseModel], fixture: str) -> None:
    data = _load(fixture)
    instance = model_cls.model_validate(data)
    json_value = instance.to_json_value()  # type: ignore[attr-defined]
    assert isinstance(json_value, dict)
    # `to_json_value()` produces a canonical-encoding-stable form: a second
    # validate/dump round-trip yields identical canonical bytes.
    first = canonicalize(json_value)
    reparsed = model_cls.model_validate(json_value)
    second = canonicalize(reparsed.to_json_value())  # type: ignore[attr-defined]
    assert first == second
    # Top-level key set matches the source fixture (order-independent, mirrors
    # the JSON Schema's `required` + `additionalProperties: false` surface).
    assert set(json_value.keys()) == set(data.keys())


@pytest.mark.parametrize("event_type", list(LedgerEventType))
def test_ledger_entry_accepts_all_event_types(event_type: LedgerEventType) -> None:
    data = _load("ledger_entry.example.json")
    data["event_type"] = event_type.value
    entry = LedgerEntry.model_validate(data)
    assert entry.event_type is event_type


def test_ledger_entry_rejects_unknown_event_type() -> None:
    data = _load("ledger_entry.example.json")
    data["event_type"] = "NOT_A_REAL_EVENT"
    with pytest.raises(ValidationError):
        LedgerEntry.model_validate(data)
