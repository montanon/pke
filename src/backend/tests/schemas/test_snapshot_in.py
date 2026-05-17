"""Unit tests for ``SnapshotCommitmentIn`` — request validation + canonical body.

Covers HLAM-62 acceptance criteria #1–#5 and the edge-case rejection matrix
documented in the testing plan comment on the Jira issue.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from pke_backend.crypto import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import EncodingError
from pke_backend.protocol.snapshot import MetadataPolicy
from pke_backend.schemas.snapshot import (
    OWNER_SIGNING_PUBLIC_KEY_BYTES,
    SnapshotCommitmentIn,
)

CIPHERTEXT_HASH_LEN = 32
SESSION_NONCE_LEN = 16
SIGNATURE_LEN = 64


def _b64(data: bytes) -> str:
    return b64url_encode(data)


def _valid_body() -> dict[str, Any]:
    """Baseline body whose binary fields decode to the required byte lengths."""
    return {
        "type": "snapshot_commitment",
        "version": "0.1",
        "snapshot_id": "snap_test_001",
        "ciphertext_hash": _b64(b"\x11" * CIPHERTEXT_HASH_LEN),
        "owner_signing_public_key": _b64(b"\x04" + b"\x22" * 64),
        "owner_encryption_public_key": _b64(b"\x04" + b"\x33" * 64),
        "capture_timestamp": "2026-05-15T00:00:00Z",
        "metadata_policy": {
            "location_public": False,
            "location_precision": "not_public",
            "media_type": "photo",
        },
        "session_nonce": _b64(b"\x44" * SESSION_NONCE_LEN),
        "owner_signature": _b64(b"\x55" * SIGNATURE_LEN),
    }


# ---------------------------------------------------------------------------
# AC #1 — well-formed body validates cleanly
# ---------------------------------------------------------------------------


def test_valid_body_validates_cleanly() -> None:
    body = SnapshotCommitmentIn.model_validate(_valid_body())

    assert body.type == "snapshot_commitment"
    assert body.version == "0.1"
    assert body.snapshot_id == "snap_test_001"
    assert isinstance(body.ciphertext_hash, bytes)
    assert len(body.ciphertext_hash) == CIPHERTEXT_HASH_LEN
    assert isinstance(body.owner_signing_public_key, bytes)
    assert len(body.owner_signing_public_key) == OWNER_SIGNING_PUBLIC_KEY_BYTES
    assert isinstance(body.owner_encryption_public_key, bytes)
    assert isinstance(body.capture_timestamp, datetime)
    assert body.capture_timestamp.tzinfo is UTC
    assert isinstance(body.metadata_policy, MetadataPolicy)
    assert isinstance(body.session_nonce, bytes)
    assert len(body.session_nonce) == SESSION_NONCE_LEN
    assert isinstance(body.owner_signature, bytes)
    assert len(body.owner_signature) == SIGNATURE_LEN


# ---------------------------------------------------------------------------
# AC #2 — missing owner_signature
# ---------------------------------------------------------------------------


def test_missing_owner_signature_raises() -> None:
    body = _valid_body()
    del body["owner_signature"]

    with pytest.raises(ValidationError) as exc_info:
        SnapshotCommitmentIn.model_validate(body)

    errors = exc_info.value.errors()
    missing = [e for e in errors if e["loc"] == ("owner_signature",) and e["type"] == "missing"]
    assert len(missing) == 1


# ---------------------------------------------------------------------------
# AC #3 — location_public=True without location_precision still passes
# ---------------------------------------------------------------------------


def test_location_public_without_precision_validates() -> None:
    body = _valid_body()
    body["metadata_policy"] = {"location_public": True, "media_type": "photo"}

    parsed = SnapshotCommitmentIn.model_validate(body)

    assert parsed.metadata_policy.location_public is True
    assert parsed.metadata_policy.location_precision is None


# ---------------------------------------------------------------------------
# AC #4 — canonical_body_bytes matches canonicalize(dump_exclude_signature)
# ---------------------------------------------------------------------------


def test_canonical_body_bytes_matches_dump_exclude_signature() -> None:
    body = SnapshotCommitmentIn.model_validate(_valid_body())

    expected = canonicalize(
        body.model_dump(mode="json", by_alias=False, exclude={"owner_signature"}),
    )

    assert body.canonical_body_bytes() == expected


def test_canonical_body_bytes_excludes_signature() -> None:
    body = SnapshotCommitmentIn.model_validate(_valid_body())

    canonical = body.canonical_body_bytes()

    assert b"owner_signature" not in canonical
    assert body.owner_signature  # signature value is still on the model


def test_canonical_body_bytes_stable_under_signature_change() -> None:
    body_a_input = _valid_body()
    body_b_input = deepcopy(body_a_input)
    body_b_input["owner_signature"] = _b64(b"\xaa" * SIGNATURE_LEN)

    body_a = SnapshotCommitmentIn.model_validate(body_a_input)
    body_b = SnapshotCommitmentIn.model_validate(body_b_input)

    assert body_a.canonical_body_bytes() == body_b.canonical_body_bytes()
    assert body_a.owner_signature != body_b.owner_signature


# ---------------------------------------------------------------------------
# AC #5 — deterministic across repeated calls
# ---------------------------------------------------------------------------


def test_canonical_body_bytes_deterministic() -> None:
    body = SnapshotCommitmentIn.model_validate(_valid_body())

    first = body.canonical_body_bytes()
    second = body.canonical_body_bytes()

    assert first == second
    assert isinstance(first, bytes)


# ---------------------------------------------------------------------------
# AC #4 — canonical bytes are sort-keys minified UTF-8 JSON
# ---------------------------------------------------------------------------


def test_canonical_body_has_sorted_top_level_keys() -> None:
    body = SnapshotCommitmentIn.model_validate(_valid_body())

    canonical = body.canonical_body_bytes().decode("utf-8")

    # Top-level keys appear in lexicographic order. Locate each key's offset and
    # assert the offsets are monotonically increasing.
    expected_keys = sorted(
        [
            "capture_timestamp",
            "ciphertext_hash",
            "metadata_policy",
            "owner_encryption_public_key",
            "owner_signing_public_key",
            "session_nonce",
            "snapshot_id",
            "type",
            "version",
        ],
    )
    offsets = [canonical.index(f'"{key}":') for key in expected_keys]
    assert offsets == sorted(offsets)
    assert "owner_signature" not in canonical


# ---------------------------------------------------------------------------
# Edge cases — rejection matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "raw_value", "error_substring"),
    [
        # Length checks on binary fields — schema layer raises ValueError → ValidationError.
        ("ciphertext_hash", _b64(b"\x00" * (CIPHERTEXT_HASH_LEN - 1)), "expected 32-byte"),
        ("ciphertext_hash", _b64(b"\x00" * (CIPHERTEXT_HASH_LEN + 1)), "expected 32-byte"),
        ("session_nonce", _b64(b"\x00" * (SESSION_NONCE_LEN - 1)), "expected 16-byte"),
        ("session_nonce", _b64(b"\x00" * (SESSION_NONCE_LEN + 1)), "expected 16-byte"),
        ("owner_signing_public_key", _b64(b"\x02" + b"\x00" * 32), "expected 65-byte uncompressed"),
        ("owner_signing_public_key", _b64(b"\x00" * 64), "expected 65-byte uncompressed"),
        # capture_timestamp must carry an explicit Z suffix per HLAM-3.
        ("capture_timestamp", "2026-05-15T00:00:00+00:00", "must end with 'Z'"),
    ],
)
def test_invalid_field_raises_validation_error(
    field: str,
    raw_value: str,
    error_substring: str,
) -> None:
    body = _valid_body()
    body[field] = raw_value

    with pytest.raises(ValidationError) as exc_info:
        SnapshotCommitmentIn.model_validate(body)

    errors = exc_info.value.errors()
    matching = [e for e in errors if field in e["loc"]]
    assert matching, f"no validation error referenced {field}; got {errors!r}"
    assert any(
        error_substring in str(e.get("msg", "")) or error_substring in str(e.get("ctx", {})) for e in matching
    ), f"none of {matching!r} mention {error_substring!r}"


@pytest.mark.parametrize(
    ("field", "raw_value"),
    [
        # Padded base64 — HLAM-3 forbids padding.
        ("ciphertext_hash", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        # Standard-alphabet character (+, /) outside base64url alphabet.
        ("session_nonce", "AAAA+AAAAAAAAAAAAAAAAA"),
    ],
)
def test_invalid_base64url_input_rejected(field: str, raw_value: str) -> None:
    """Bad base64url is rejected — either as ValidationError or EncodingError.

    The protocol layer's ``_decode_b64url`` does not catch ``EncodingError`` and
    re-raise as ``ValueError`` (Pydantic only wraps the latter into
    ``ValidationError``). Existing protocol tests document the same dual
    behaviour with ``pytest.raises((ValidationError, EncodingError))``. The
    rejection itself — not the exception class — is what matters for security.
    """
    body = _valid_body()
    body[field] = raw_value

    with pytest.raises((ValidationError, EncodingError)):
        SnapshotCommitmentIn.model_validate(body)


def test_extra_top_level_field_rejected() -> None:
    body = _valid_body()
    body["surprise"] = "x"

    with pytest.raises(ValidationError) as exc_info:
        SnapshotCommitmentIn.model_validate(body)

    errors = exc_info.value.errors()
    assert any(e["type"] == "extra_forbidden" and "surprise" in e["loc"] for e in errors)


def test_type_must_be_snapshot_commitment_literal() -> None:
    body = _valid_body()
    body["type"] = "witness_attestation"

    with pytest.raises(ValidationError) as exc_info:
        SnapshotCommitmentIn.model_validate(body)

    errors = exc_info.value.errors()
    assert any("type" in e["loc"] for e in errors)


@pytest.mark.parametrize("missing_field", ["media_type", "location_public"])
def test_metadata_policy_required_field_missing(missing_field: str) -> None:
    body = _valid_body()
    del body["metadata_policy"][missing_field]

    with pytest.raises(ValidationError) as exc_info:
        SnapshotCommitmentIn.model_validate(body)

    errors = exc_info.value.errors()
    assert any("metadata_policy" in e["loc"] and missing_field in e["loc"] and e["type"] == "missing" for e in errors)
