"""Structural parity between ``SnapshotCommitmentIn`` and the protocol layer.

Catches drift if either ``protocol.SnapshotCommitment`` or
``schemas.SnapshotCommitmentIn`` adds, removes, or renames a field — drift
that would silently change ``canonical_body_bytes()`` output and break every
prior signature.
"""

from __future__ import annotations

from copy import deepcopy

from pke_backend.crypto import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.protocol.snapshot import SnapshotCommitment
from pke_backend.schemas.snapshot import SnapshotCommitmentIn


def test_snapshot_commitment_in_is_subclass_of_protocol_model() -> None:
    assert issubclass(SnapshotCommitmentIn, SnapshotCommitment)


def test_snapshot_commitment_in_fields_equal_protocol_fields() -> None:
    assert set(SnapshotCommitmentIn.model_fields.keys()) == set(
        SnapshotCommitment.model_fields.keys(),
    )


def test_snapshot_commitment_in_inherits_extra_forbid() -> None:
    assert SnapshotCommitmentIn.model_config["extra"] == "forbid"


def test_to_json_value_is_not_the_signed_body() -> None:
    """Guard against future callers mistaking ``to_json_value()`` for the signed body.

    The inherited ``to_json_value()`` mixin returns the *full* payload, including
    ``owner_signature``. Only :meth:`SnapshotCommitmentIn.canonical_body_bytes`
    drops the signature field per HLAM-3 §"Signed-body rule". These two paths
    must always differ — if they ever produce the same bytes, the signed-body
    semantics are broken.
    """
    body = SnapshotCommitmentIn.model_validate(
        {
            "type": "snapshot_commitment",
            "version": "0.1",
            "snapshot_id": "snap_parity",
            "ciphertext_hash": b64url_encode(b"\x11" * 32),
            "owner_signing_public_key": b64url_encode(b"\x04" + b"\x22" * 64),
            "owner_encryption_public_key": b64url_encode(b"\x04" + b"\x33" * 64),
            "capture_timestamp": "2026-05-15T00:00:00Z",
            "metadata_policy": {"location_public": False, "media_type": "photo"},
            "session_nonce": b64url_encode(b"\x44" * 16),
            "owner_signature": b64url_encode(b"\x55" * 64),
        },
    )

    full_payload_bytes = canonicalize(body.to_json_value())
    signed_body_bytes = body.canonical_body_bytes()

    assert full_payload_bytes != signed_body_bytes
    assert b"owner_signature" in full_payload_bytes
    assert b"owner_signature" not in signed_body_bytes

    # Confirm the *only* difference is the owner_signature key — i.e. the two
    # paths agree on the rest of the payload byte-for-byte.
    full_dict = deepcopy(body.to_json_value())
    assert isinstance(full_dict, dict)
    full_dict.pop("owner_signature")
    assert canonicalize(full_dict) == signed_body_bytes
