"""HTTP request/response models for the snapshot commitment endpoint.

Distinct from ``pke_backend.protocol.snapshot``: the protocol module is the
on-the-wire mirror of ``shared/schemas/snapshot_commitment.json`` and stays
permissive about binary-field lengths so cross-language fixtures keep loading.
The models in this module add endpoint-specific constraints (32-byte SHA-256
digests, 16-byte session nonces, 65-byte uncompressed P-256 public keys) and
expose ``canonical_body_bytes()`` so the ``POST /snapshots`` handler can hand
the exact bytes the owner signed to the signature verifier — no second
canonicalization path, no chance of drift.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final, cast

from pydantic import BaseModel, ConfigDict, field_serializer, field_validator

from pke_backend.crypto import canonicalize
from pke_backend.crypto.encoding import hex_encode
from pke_backend.crypto.types import JsonValue
from pke_backend.models.snapshot import (
    CIPHERTEXT_HASH_BYTES,
    SESSION_NONCE_BYTES,
    Snapshot,
)
from pke_backend.protocol.snapshot import MetadataPolicy, SnapshotCommitment

__all__ = [
    "OWNER_SIGNING_PUBLIC_KEY_BYTES",
    "SnapshotCommitmentIn",
    "SnapshotOut",
]

# Uncompressed P-256 public key: 0x04 || X(32) || Y(32). Compressed (33 bytes,
# leading 0x02/0x03) and hybrid (65 bytes, leading 0x06/0x07) encodings are
# rejected per HLAM-3 §"ECDSA" — wire format is uncompressed only.
OWNER_SIGNING_PUBLIC_KEY_BYTES: Final[int] = 65


def _check_length(field: str, value: bytes, expected: int, description: str) -> bytes:
    if len(value) != expected:
        # Error message carries the byte counts only — never the raw bytes —
        # to match the discipline in ``pke_backend.crypto.encoding``.
        raise ValueError(
            f"{field}: expected {expected}-byte {description}, got {len(value)} bytes",
        )
    return value


class SnapshotCommitmentIn(SnapshotCommitment):
    """Request body for ``POST /snapshots``.

    Inherits every field, ``Base64UrlBytes`` decoding, ``UTCDatetime`` parsing,
    and ``extra="forbid"`` from :class:`SnapshotCommitment`. Adds byte-length
    validation for the three security-critical binary fields and exposes
    :meth:`canonical_body_bytes` — the single source of the signed-body bytes
    the verifier must reproduce.
    """

    @field_validator("ciphertext_hash", mode="after")
    @classmethod
    def _check_ciphertext_hash_length(cls, value: bytes) -> bytes:
        return _check_length(
            "ciphertext_hash",
            value,
            CIPHERTEXT_HASH_BYTES,
            "SHA-256 digest",
        )

    @field_validator("session_nonce", mode="after")
    @classmethod
    def _check_session_nonce_length(cls, value: bytes) -> bytes:
        return _check_length(
            "session_nonce",
            value,
            SESSION_NONCE_BYTES,
            "session nonce",
        )

    @field_validator("owner_signing_public_key", mode="after")
    @classmethod
    def _check_owner_signing_public_key_length(cls, value: bytes) -> bytes:
        return _check_length(
            "owner_signing_public_key",
            value,
            OWNER_SIGNING_PUBLIC_KEY_BYTES,
            "uncompressed P-256 public key",
        )

    def canonical_body_bytes(self) -> bytes:
        """Return the canonical-JSON bytes that the owner's signature covers.

        Implements HLAM-3 §"Signed-body rule": serialise the full payload minus
        the ``owner_signature`` field, then canonicalize via
        :func:`pke_backend.crypto.canonicalize`. Deterministic by construction —
        ``model_dump(mode="json")`` produces JSON primitives only, and
        ``canonicalize`` sorts keys lexicographically.

        The inherited ``to_json_value()`` returns the **full** payload including
        ``owner_signature`` and is therefore not the signed body. Always use
        this method for verification.
        """
        payload = self.model_dump(
            mode="json",
            by_alias=False,
            exclude={"owner_signature"},
        )
        return canonicalize(cast("JsonValue", payload))


class SnapshotOut(BaseModel):
    """Response body for ``POST /snapshots`` and ``GET /snapshots/{id}``.

    All binary fields are hex-encoded for operator and auditor readability.
    Timestamps serialise with a ``Z`` suffix to match the wire-format
    convention used in :class:`SnapshotCommitment`. The model is frozen so a
    constructed response cannot be mutated downstream.

    ``frozen`` reflects whether a :class:`pke_backend.models.freeze.Freeze`
    row exists for ``snapshot_id`` at response time — derived via a LEFT JOIN
    in :func:`pke_backend.services.snapshots.fetch_snapshot_for_response`. The
    field is part of the F1/F5 cross-feature contract surfaced by HLAM-65.

    ``blob_url`` is the canonical relative URL the recipient should GET to
    stream the encrypted blob. It is intentionally relative so the value is
    portable behind a reverse proxy (the public hostname is the
    deployment's, not the API's, to advertise).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    ciphertext_hash: str
    owner_signing_public_key: str
    owner_encryption_public_key: str
    capture_timestamp: datetime
    metadata_policy: MetadataPolicy
    session_nonce: str
    version: str
    blob_storage_uri: str
    blob_url: str
    frozen: bool
    created_at: datetime
    owner_signature: str
    ledger_entry_hash: str

    @field_serializer("capture_timestamp", "created_at")
    def _serialize_utc_z(self, value: datetime) -> str:
        iso = value.isoformat()
        if iso.endswith("+00:00"):
            return iso[: -len("+00:00")] + "Z"
        return iso

    @classmethod
    def from_persisted(
        cls,
        snapshot: Snapshot,
        ledger_entry_hash: bytes,
        *,
        frozen: bool = False,
    ) -> SnapshotOut:
        """Adapt a persisted :class:`Snapshot` row + ledger anchor into a response.

        ``ledger_entry_hash`` is the bytes produced by the F1 ledger append in
        the same transaction — it isn't part of the ORM row because it belongs
        to the ledger table, not the snapshots table.

        ``frozen`` defaults to ``False`` so existing call sites (the unit
        tests in this package, future POST handler) keep working without
        churn; HLAM-65's GET handler always supplies the joined value.
        """
        metadata_policy = MetadataPolicy.model_validate(snapshot.metadata_policy)
        return cls(
            snapshot_id=str(snapshot.snapshot_id),
            ciphertext_hash=hex_encode(snapshot.ciphertext_hash),
            owner_signing_public_key=hex_encode(snapshot.owner_signing_public_key),
            owner_encryption_public_key=hex_encode(snapshot.owner_encryption_public_key),
            capture_timestamp=snapshot.capture_timestamp,
            metadata_policy=metadata_policy,
            session_nonce=hex_encode(snapshot.session_nonce),
            version=snapshot.version,
            blob_storage_uri=snapshot.blob_storage_uri,
            blob_url=f"/snapshots/{snapshot.snapshot_id}/blob",
            frozen=frozen,
            created_at=snapshot.created_at,
            owner_signature=hex_encode(snapshot.owner_signature),
            ledger_entry_hash=hex_encode(ledger_entry_hash),
        )
