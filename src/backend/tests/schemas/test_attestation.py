from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from pydantic import ValidationError

import pke_backend.schemas as schemas_pkg
from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import EncodingError
from pke_backend.crypto.types import JsonValue
from pke_backend.models.attestation import WITNESS_ATTESTATION_VERSION
from pke_backend.models.attestation import WitnessAttestation as WitnessAttestationORM
from pke_backend.protocol.attestation import WitnessAttestation as ProtocolWitnessAttestation
from pke_backend.schemas import (
    ProximityClaim,
    WitnessAttestationIn,
    WitnessAttestationOut,
)

# 65-byte uncompressed P-256 point placeholder: 0x04 || 32 bytes X || 32 bytes Y.
_PUBKEY_BYTES = b"\x04" + b"\x01" * 32 + b"\x02" * 32
# 64-byte raw P1363 signature placeholder: 32 bytes r || 32 bytes s.
_SIGNATURE_BYTES = b"\x03" * 64
# 32-byte SHA-256 digest placeholder.
_HASH_BYTES = b"\x04" * 32
# 16-byte session-nonce placeholder (matches HLAM-61 SESSION_NONCE_BYTES).
_NONCE_BYTES = b"\x05" * 16
# Owner-side 65-byte P-256 point — distinct from the witness key for clarity.
_OWNER_PUBKEY_BYTES = b"\x04" + b"\x06" * 32 + b"\x07" * 32


def _valid_payload() -> dict[str, Any]:
    return {
        "type": "witness_attestation",
        "version": "0.1",
        "snapshot_id": "snap_test_001",
        "ciphertext_hash": b64url_encode(_HASH_BYTES),
        "session_nonce": b64url_encode(_NONCE_BYTES),
        "owner_signing_public_key": b64url_encode(_OWNER_PUBKEY_BYTES),
        "witness_signing_public_key": b64url_encode(_PUBKEY_BYTES),
        "witness_timestamp": "2026-05-15T00:00:30Z",
        "transport": "multipeerconnectivity",
        "proximity_claim": {
            "method": "nearby_session",
            "exact_location_public": False,
        },
        "witness_signature": b64url_encode(_SIGNATURE_BYTES),
    }


def _build_orm_row(*, proximity_claim_extra: dict[str, Any] | None = None) -> WitnessAttestationORM:
    proximity_claim: dict[str, Any] = {
        "method": "nearby_session",
        "exact_location_public": False,
    }
    if proximity_claim_extra is not None:
        proximity_claim.update(proximity_claim_extra)
    row = WitnessAttestationORM(
        snapshot_id=uuid.UUID("00000000-0000-4000-8000-000000000001"),
        witness_signing_public_key=b64url_encode(_PUBKEY_BYTES),
        witness_timestamp=datetime(2026, 5, 15, 0, 0, 30, tzinfo=UTC),
        transport="multipeerconnectivity",
        proximity_claim=proximity_claim,
        witness_signature=_SIGNATURE_BYTES,
        version=WITNESS_ATTESTATION_VERSION,
        created_at=datetime(2026, 5, 15, 0, 0, 31, tzinfo=UTC),
    )
    # `id` is autoincrement at the DB layer; for unit tests we set it directly.
    row.id = 42
    return row


# ── AC #1 ─────────────────────────────────────────────────────────────────────


def test_valid_payload_validates_and_populates_all_fields() -> None:
    instance = WitnessAttestationIn.model_validate(_valid_payload())
    assert instance.type == "witness_attestation"
    assert instance.version == "0.1"
    assert instance.snapshot_id == "snap_test_001"
    assert instance.ciphertext_hash == _HASH_BYTES
    assert instance.session_nonce == _NONCE_BYTES
    assert instance.owner_signing_public_key == _OWNER_PUBKEY_BYTES
    assert instance.witness_signing_public_key == _PUBKEY_BYTES
    assert instance.witness_timestamp.tzinfo is UTC
    assert instance.transport == "multipeerconnectivity"
    assert instance.proximity_claim.method == "nearby_session"
    assert instance.proximity_claim.exact_location_public is False
    assert instance.witness_signature == _SIGNATURE_BYTES


# ── AC #2 ─────────────────────────────────────────────────────────────────────


def test_canonical_body_bytes_is_deterministic() -> None:
    payload = _valid_payload()
    first = WitnessAttestationIn.model_validate(payload).canonical_body_bytes()
    second = WitnessAttestationIn.model_validate(payload).canonical_body_bytes()
    assert first == second
    assert first
    assert first.endswith(b"}")


# ── AC #3 ─────────────────────────────────────────────────────────────────────


def test_canonical_body_bytes_matches_canonicalize_minus_signature() -> None:
    instance = WitnessAttestationIn.model_validate(_valid_payload())
    expected = canonicalize(
        cast(
            "JsonValue",
            instance.model_dump(mode="json", by_alias=True, exclude={"witness_signature"}),
        ),
    )
    assert instance.canonical_body_bytes() == expected
    assert b"witness_signature" not in instance.canonical_body_bytes()


def test_dump_exclude_signature_omits_witness_signature_key() -> None:
    instance = WitnessAttestationIn.model_validate(_valid_payload())
    dumped = instance.dump_exclude_signature()
    assert isinstance(dumped, dict)
    assert "witness_signature" not in dumped


# ── AC #4 ─────────────────────────────────────────────────────────────────────


def test_missing_witness_signature_raises() -> None:
    payload = _valid_payload()
    del payload["witness_signature"]
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert ("witness_signature",) in locs


# ── AC #5 ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("wrong_size", [0, 1, 63, 65, 128])
def test_witness_signature_wrong_length_raises(wrong_size: int) -> None:
    payload = _valid_payload()
    payload["witness_signature"] = b64url_encode(b"\x00" * wrong_size)
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert ("witness_signature",) in locs


# ── AC #6 ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("wrong_size", [0, 1, 32, 64, 66, 128])
def test_witness_signing_public_key_wrong_length_raises(wrong_size: int) -> None:
    payload = _valid_payload()
    payload["witness_signing_public_key"] = b64url_encode(b"\x00" * wrong_size)
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert ("witness_signing_public_key",) in locs


# ── AC #7 ─────────────────────────────────────────────────────────────────────


def test_from_persisted_constructs_response_with_hex_hash_and_iso_timestamps() -> None:
    orm = _build_orm_row()
    ledger_entry_hash = b"\xab" * 32

    out = WitnessAttestationOut.from_persisted(
        attestation=orm,
        ledger_entry_hash=ledger_entry_hash,
    )

    assert out.attestation_id == orm.id
    assert out.snapshot_id == str(orm.snapshot_id)
    assert out.witness_signing_public_key == orm.witness_signing_public_key
    assert out.transport == orm.transport
    assert out.version == orm.version
    assert out.ledger_entry_hash == ledger_entry_hash.hex()
    assert len(out.ledger_entry_hash) == 64
    assert out.ledger_entry_hash == out.ledger_entry_hash.lower()

    dumped = out.model_dump(mode="json")
    assert dumped["witness_timestamp"].endswith("Z")
    assert dumped["created_at"].endswith("Z")
    assert dumped["ledger_entry_hash"] == ledger_entry_hash.hex()


def test_from_persisted_rejects_non_32_byte_ledger_entry_hash() -> None:
    orm = _build_orm_row()
    with pytest.raises(ValueError, match="ledger_entry_hash must be 32 bytes"):
        WitnessAttestationOut.from_persisted(
            attestation=orm,
            ledger_entry_hash=b"\x00" * 31,
        )


def test_from_persisted_rejects_non_dict_proximity_claim() -> None:
    orm = _build_orm_row()
    # JSONB can decode to anything; guard against future ORM drift where the
    # column is widened or a corrupted row hydrates as e.g. a list.
    orm.proximity_claim = ["not", "a", "dict"]  # type: ignore[assignment]
    with pytest.raises(ValueError, match="proximity_claim must be a dict"):
        WitnessAttestationOut.from_persisted(
            attestation=orm,
            ledger_entry_hash=b"\x00" * 32,
        )


def test_from_persisted_round_trips_proximity_claim_jsonb_dropping_unknown_fields() -> None:
    orm = _build_orm_row(proximity_claim_extra={"rssi_dbm": -42, "extra_unknown": "x"})
    out = WitnessAttestationOut.from_persisted(
        attestation=orm,
        ledger_entry_hash=b"\xcd" * 32,
    )
    assert out.proximity_claim.method == "nearby_session"
    assert out.proximity_claim.exact_location_public is False
    assert not hasattr(out.proximity_claim, "rssi_dbm")
    assert not hasattr(out.proximity_claim, "extra_unknown")
    dumped = out.model_dump(mode="json")
    assert dumped["proximity_claim"] == {
        "method": "nearby_session",
        "exact_location_public": False,
    }


# ── Edge case: padded base64 rejected (HLAM-3) ────────────────────────────────


def test_padded_base64_in_witness_signature_raises() -> None:
    payload = _valid_payload()
    payload["witness_signature"] = b64url_encode(_SIGNATURE_BYTES) + "=="
    # `b64url_decode` raises `EncodingError`, not `ValueError`, so Pydantic
    # does not wrap it. Match the convention from `tests/protocol/test_types.py`.
    with pytest.raises((ValidationError, EncodingError)):
        WitnessAttestationIn.model_validate(payload)


def test_padded_base64_in_witness_signing_public_key_raises() -> None:
    payload = _valid_payload()
    payload["witness_signing_public_key"] = b64url_encode(_PUBKEY_BYTES) + "="
    with pytest.raises((ValidationError, EncodingError)):
        WitnessAttestationIn.model_validate(payload)


# ── Edge case: unknown top-level field rejected ───────────────────────────────


def test_unknown_top_level_field_raises() -> None:
    payload = _valid_payload()
    payload["__extra__"] = "x"
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert ("__extra__",) in locs


# ── Edge case: unknown proximity_claim sub-field silently dropped ─────────────


def test_unknown_proximity_claim_field_ignored_and_not_in_canonical_bytes() -> None:
    payload = _valid_payload()
    payload["proximity_claim"]["rssi_dbm"] = -42
    instance = WitnessAttestationIn.model_validate(payload)
    assert not hasattr(instance.proximity_claim, "rssi_dbm")
    assert b"rssi_dbm" not in instance.canonical_body_bytes()


# ── Edge case: timestamp without trailing Z rejected ──────────────────────────


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "2026-05-17T00:00:00+00:00",  # offset, no trailing Z
        "2026-05-17T00:00:00",  # naive
        "2026-05-17",  # date-only
    ],
)
def test_witness_timestamp_without_z_suffix_raises(bad_timestamp: str) -> None:
    payload = _valid_payload()
    payload["witness_timestamp"] = bad_timestamp
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert ("witness_timestamp",) in locs


# ── Edge case: empty transport rejected ───────────────────────────────────────


def test_empty_transport_raises() -> None:
    payload = _valid_payload()
    payload["transport"] = ""
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert ("transport",) in locs


# ── Edge case: DoS-defensive max_length on string fields ──────────────────────


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("snapshot_id", 128),
        ("transport", 64),
        ("version", 16),
    ],
)
def test_oversized_string_field_raises(field: str, limit: int) -> None:
    payload = _valid_payload()
    payload[field] = "x" * (limit + 1)
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert (field,) in locs


def test_oversized_proximity_claim_method_raises() -> None:
    payload = _valid_payload()
    payload["proximity_claim"]["method"] = "x" * 65
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert ("proximity_claim", "method") in locs


# ── Edge case: wrong `type` literal rejected ──────────────────────────────────


def test_wrong_type_literal_raises() -> None:
    payload = _valid_payload()
    payload["type"] = "snapshot_commitment"
    with pytest.raises(ValidationError) as excinfo:
        WitnessAttestationIn.model_validate(payload)
    locs = {tuple(err["loc"]) for err in excinfo.value.errors()}
    assert ("type",) in locs


# ── Module surface ────────────────────────────────────────────────────────────


def test_public_exports_are_accessible_from_schemas_package() -> None:
    expected = {"ProximityClaim", "WitnessAttestationIn", "WitnessAttestationOut"}
    assert expected <= set(schemas_pkg.__all__)
    # Names resolve to the same objects exposed by the leaf module.
    assert schemas_pkg.WitnessAttestationIn is WitnessAttestationIn
    assert schemas_pkg.WitnessAttestationOut is WitnessAttestationOut
    assert schemas_pkg.ProximityClaim is ProximityClaim


# ── Cross-layer parity with protocol mirror ───────────────────────────────────


def test_canonical_body_matches_protocol_layer_on_same_payload() -> None:
    payload = _valid_payload()
    schemas_instance = WitnessAttestationIn.model_validate(payload)
    protocol_instance = ProtocolWitnessAttestation.model_validate(payload)
    protocol_json = protocol_instance.to_json_value()
    assert isinstance(protocol_json, dict)
    protocol_minus_signature = {k: v for k, v in protocol_json.items() if k != "witness_signature"}
    assert canonicalize(cast("JsonValue", protocol_minus_signature)) == schemas_instance.canonical_body_bytes()


# ── Defensive: schemas-layer output is decodable JSON ─────────────────────────


def test_canonical_body_bytes_is_decodable_json() -> None:
    instance = WitnessAttestationIn.model_validate(_valid_payload())
    decoded = json.loads(instance.canonical_body_bytes())
    assert decoded["type"] == "witness_attestation"
    assert "witness_signature" not in decoded
