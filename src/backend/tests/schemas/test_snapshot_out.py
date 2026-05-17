"""Unit tests for ``SnapshotOut.from_persisted`` — response adapter.

Covers HLAM-62 acceptance criterion #6 and the hardening checks in the testing
plan (frozen response, extra-field rejection, lowercase hex).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from pke_backend.models.snapshot import Snapshot
from pke_backend.schemas.snapshot import SnapshotOut

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)


def _make_snapshot() -> Snapshot:
    """In-memory ORM instance — never added to a session."""
    snap = Snapshot()
    snap.snapshot_id = uuid.UUID("12345678-1234-5678-1234-567812345678")
    snap.ciphertext_hash = bytes.fromhex("aa" * 32)
    snap.owner_signing_public_key = bytes.fromhex("04" + "bb" * 64)
    snap.owner_encryption_public_key = bytes.fromhex("04" + "ee" * 64)
    snap.capture_timestamp = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)
    snap.metadata_policy = {
        "location_public": False,
        "media_type": "photo",
    }
    snap.session_nonce = bytes.fromhex("cc" * 16)
    snap.owner_signature = bytes.fromhex("dd" * 64)
    snap.version = "0.1"
    snap.blob_storage_uri = "file:///blobs/12345678-1234-5678-1234-567812345678/blob.bin"
    snap.created_at = datetime(2026, 5, 15, 12, 0, 5, tzinfo=UTC)
    return snap


LEDGER_HASH = bytes.fromhex("ff" * 32)


# ---------------------------------------------------------------------------
# AC #6 — populated response with hex-encoded hashes + ISO-8601 timestamps
# ---------------------------------------------------------------------------


def test_from_persisted_returns_populated_response() -> None:
    out = SnapshotOut.from_persisted(_make_snapshot(), LEDGER_HASH)

    assert isinstance(out, SnapshotOut)
    assert out.snapshot_id
    assert out.ciphertext_hash
    assert out.owner_signing_public_key
    assert out.owner_encryption_public_key
    assert isinstance(out.capture_timestamp, datetime)
    assert out.session_nonce
    assert out.version == "0.1"
    assert out.blob_storage_uri.endswith("blob.bin")
    assert isinstance(out.created_at, datetime)
    assert out.owner_signature
    assert out.ledger_entry_hash


def test_from_persisted_hex_encodes_all_binary_fields() -> None:
    out = SnapshotOut.from_persisted(_make_snapshot(), LEDGER_HASH)

    assert out.ciphertext_hash == "aa" * 32
    assert out.owner_signing_public_key == "04" + "bb" * 64
    assert out.owner_encryption_public_key == "04" + "ee" * 64
    assert out.session_nonce == "cc" * 16
    assert out.owner_signature == "dd" * 64
    assert out.ledger_entry_hash == "ff" * 32

    # All hex outputs are lowercase per ``hex_encode``'s contract.
    for value in (
        out.ciphertext_hash,
        out.owner_signing_public_key,
        out.owner_encryption_public_key,
        out.session_nonce,
        out.owner_signature,
        out.ledger_entry_hash,
    ):
        assert re.fullmatch(r"[0-9a-f]+", value), f"non-lowercase-hex value: {value!r}"


def test_from_persisted_snapshot_id_is_uuid_string() -> None:
    out = SnapshotOut.from_persisted(_make_snapshot(), LEDGER_HASH)

    assert isinstance(out.snapshot_id, str)
    assert out.snapshot_id == "12345678-1234-5678-1234-567812345678"
    assert UUID_REGEX.match(out.snapshot_id)


def test_from_persisted_timestamps_serialise_with_z_suffix() -> None:
    out = SnapshotOut.from_persisted(_make_snapshot(), LEDGER_HASH)

    dumped = out.model_dump_json()

    assert '"capture_timestamp":"2026-05-15T12:00:00Z"' in dumped
    assert '"created_at":"2026-05-15T12:00:05Z"' in dumped
    assert "+00:00" not in dumped


def test_from_persisted_metadata_policy_roundtrip() -> None:
    out = SnapshotOut.from_persisted(_make_snapshot(), LEDGER_HASH)

    assert out.metadata_policy.location_public is False
    assert out.metadata_policy.media_type == "photo"
    assert out.metadata_policy.location_precision is None


def test_from_persisted_with_optional_location_precision() -> None:
    snap = _make_snapshot()
    snap.metadata_policy = {
        "location_public": True,
        "location_precision": "city",
        "media_type": "photo",
    }

    out = SnapshotOut.from_persisted(snap, LEDGER_HASH)

    assert out.metadata_policy.location_public is True
    assert out.metadata_policy.location_precision == "city"


# ---------------------------------------------------------------------------
# Hardening — frozen + extra=forbid
# ---------------------------------------------------------------------------


def test_snapshot_out_is_frozen() -> None:
    out = SnapshotOut.from_persisted(_make_snapshot(), LEDGER_HASH)

    with pytest.raises(ValidationError):
        out.snapshot_id = "mutated"


def test_snapshot_out_rejects_extra_fields() -> None:
    out = SnapshotOut.from_persisted(_make_snapshot(), LEDGER_HASH)
    serialised: dict[str, Any] = out.model_dump()
    serialised["surprise"] = "x"

    with pytest.raises(ValidationError) as exc_info:
        SnapshotOut.model_validate(serialised)

    errors = exc_info.value.errors()
    assert any(e["type"] == "extra_forbidden" and "surprise" in e["loc"] for e in errors)
