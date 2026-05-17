"""API-boundary Pydantic models for the witness-attestation endpoint.

Mirrors `src/shared/schemas/witness_attestation.json` for the HTTP request
shape (``WitnessAttestationIn``) and the response shape
(``WitnessAttestationOut``). Distinct from ``pke_backend.protocol.attestation``,
which is the on-the-wire spec mirror used by canonical-bytes parity tests:
that module's job is byte-identical round-tripping; this module's job is to
reject malformed input early and to expose the exact bytes the witness
device signed under HLAM-3's signed-body rule.

``canonical_body_bytes()`` excludes ``witness_signature`` per
``context/16_canonical_encoding.md`` §Signed-body rule and delegates to
``pke_backend.crypto.canonicalize.canonicalize`` — never re-implements
canonicalization locally. The witness-specific length checks (64-byte P1363
signature, 65-byte uncompressed P-256 public key) come from the same spec's
binary-field table. Other length checks on fields pinned to the snapshot
row (``ciphertext_hash``, ``session_nonce``, ``owner_signing_public_key``)
are deferred to the service layer (HLAM-39 #4), where the row is joined.

``ProximityClaim`` accepts unknown sub-fields (``extra="ignore"``) to leave
room for transport-specific extensions a witness device may emit; the root
``WitnessAttestationIn`` rejects unknown top-level fields. This is the
deliberate divergence from ``protocol/attestation.py``'s strict mode — the
protocol mirror must be strict for canonical-bytes determinism, the API
adapter is forgiving on the surface a third-party witness might extend.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import TYPE_CHECKING, Annotated, Final, Literal, cast

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.types import JsonValue
from pke_backend.protocol.types import Base64UrlBytes, UTCDatetime

if TYPE_CHECKING:
    from pke_backend.models.attestation import WitnessAttestation as _WitnessAttestationORM

__all__ = [
    "MAX_BATCH_ATTESTATIONS",
    "AcceptedAttestation",
    "AttestationBatchRequest",
    "AttestationBatchResponse",
    "AttestationRejectionReason",
    "ProximityClaim",
    "RejectedAttestation",
    "WitnessAttestationIn",
    "WitnessAttestationListResponse",
    "WitnessAttestationOut",
]

# HLAM-141: capturer-side cap on attestations per POST. Matches the iOS
# witness dispatcher's "50 soft cap" within a single 30-second session; the
# backend enforces it as a hard limit so an over-cap upload is rejected at
# the schema layer before any signature verification work.
MAX_BATCH_ATTESTATIONS: Final[int] = 50

# Lengths come from `context/16_canonical_encoding.md` §Binary field encoding
# on the wire. Witness signing key is uncompressed P-256: `0x04 || X || Y`,
# X and Y each 32 bytes. Witness signature is raw P1363, r||s, each 32 bytes.
_WITNESS_PUBLIC_KEY_BYTES: Final[int] = 65
_WITNESS_SIGNATURE_BYTES: Final[int] = 64
# SHA-256 digest length — used to gate `from_persisted` against a malformed
# ledger entry hash from the service layer.
_LEDGER_ENTRY_HASH_BYTES: Final[int] = 32

# DoS-defensive caps on unbounded string fields. The base64url-bytes fields
# are not length-capped at this layer; FastAPI's request-size middleware is
# the right place for that broader bound, and the service-layer joins
# (HLAM-39 #4) re-bound them against the snapshot row.
_SNAPSHOT_ID_MAX = 128
_TRANSPORT_MAX = 64  # matches the `String(64)` column in `models/attestation.py`
_VERSION_MAX = 16  # matches the `String(16)` column in `models/attestation.py`
_PROXIMITY_METHOD_MAX = 64


def _require_byte_length(expected: int) -> AfterValidator:
    def _check(value: bytes) -> bytes:
        if len(value) != expected:
            raise ValueError(f"expected {expected} bytes, got {len(value)}")
        return value

    return AfterValidator(_check)


_WitnessSigningPublicKey = Annotated[
    Base64UrlBytes,
    _require_byte_length(_WITNESS_PUBLIC_KEY_BYTES),
]
_WitnessSignature = Annotated[
    Base64UrlBytes,
    _require_byte_length(_WITNESS_SIGNATURE_BYTES),
]


class ProximityClaim(BaseModel):
    """Permissive sub-model for the witness's proximity claim.

    Unknown fields are ignored, not rejected, to leave room for
    transport-specific signals (e.g. an RSSI reading) without forcing a
    schema bump. The two required fields below are the only ones the
    protocol asserts on; everything else is advisory metadata for the
    service layer.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    method: str = Field(min_length=1, max_length=_PROXIMITY_METHOD_MAX)
    exact_location_public: bool


class WitnessAttestationIn(BaseModel):
    """HTTP request model for `POST /attestations`.

    Validates the wire shape, enforces witness-specific key/signature
    lengths, and exposes ``canonical_body_bytes()`` — the exact bytes the
    witness signature must verify against in the HLAM-39 service layer.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["witness_attestation"]
    # `version` is not pinned to a Literal here: spec compatibility (refuse
    # mismatched versions per `context/16_canonical_encoding.md` §Versioning)
    # is enforced in the HLAM-39 service layer, where the policy can be
    # softened during a v0.1 → v0.2 cutover without forcing a schemas-layer
    # release. The non-empty guard catches the obvious malformed-input case.
    version: str = Field(min_length=1, max_length=_VERSION_MAX)
    snapshot_id: str = Field(min_length=1, max_length=_SNAPSHOT_ID_MAX)
    ciphertext_hash: Base64UrlBytes
    session_nonce: Base64UrlBytes
    owner_signing_public_key: Base64UrlBytes
    witness_signing_public_key: _WitnessSigningPublicKey
    witness_timestamp: UTCDatetime
    transport: str = Field(min_length=1, max_length=_TRANSPORT_MAX)
    proximity_claim: ProximityClaim
    witness_signature: _WitnessSignature

    def dump_exclude_signature(self) -> JsonValue:
        """Return the signed-body payload as a `JsonValue` (signature excluded).

        Callers MUST canonicalize via `pke_backend.crypto.canonicalize` before
        using the output as a signing/verification input. The dict produced
        here is in field-declaration order — not sorted — and is only
        signature-equivalent after the canonical encoder applies `sort_keys`.
        Use :meth:`canonical_body_bytes` for the bytes the witness signed.
        """
        return cast(
            "JsonValue",
            self.model_dump(mode="json", by_alias=True, exclude={"witness_signature"}),
        )

    def canonical_body_bytes(self) -> bytes:
        return canonicalize(self.dump_exclude_signature())


class WitnessAttestationOut(BaseModel):
    """HTTP response model for `POST /attestations`.

    Constructed via :meth:`from_persisted` from the ORM row plus the
    ledger entry hash the service layer minted. ``witness_signature`` is
    deliberately not echoed back — the caller already has it and the
    ledger hash is the receipt that proves persistence + chain anchoring.

    Response narrowing: any extra sub-fields the witness sent inside
    ``proximity_claim`` (e.g. transport-specific signals like an RSSI
    reading) are stored verbatim as JSONB on the row but stripped on the
    way out, because ``ProximityClaim`` is ``extra="ignore"``. That is
    intentional — clients see the spec-required subset; the raw JSONB is
    available to the service layer if a future schema bump promotes any
    of those signals into the response surface.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    attestation_id: int
    snapshot_id: str
    witness_signing_public_key: str
    witness_timestamp: UTCDatetime
    transport: str
    proximity_claim: ProximityClaim
    version: str
    created_at: UTCDatetime
    ledger_entry_hash: str

    @classmethod
    def from_persisted(
        cls,
        *,
        attestation: _WitnessAttestationORM,
        ledger_entry_hash: bytes,
    ) -> WitnessAttestationOut:
        if len(ledger_entry_hash) != _LEDGER_ENTRY_HASH_BYTES:
            raise ValueError(
                f"ledger_entry_hash must be {_LEDGER_ENTRY_HASH_BYTES} bytes, got {len(ledger_entry_hash)}",
            )
        proximity_claim_raw = attestation.proximity_claim
        if not isinstance(proximity_claim_raw, dict):
            raise ValueError(
                f"proximity_claim must be a dict, got {type(proximity_claim_raw).__name__}",
            )
        return cls(
            attestation_id=attestation.id,
            snapshot_id=str(attestation.snapshot_id),
            witness_signing_public_key=attestation.witness_signing_public_key,
            witness_timestamp=attestation.witness_timestamp,
            transport=attestation.transport,
            proximity_claim=ProximityClaim.model_validate(proximity_claim_raw),
            version=attestation.version,
            created_at=attestation.created_at,
            ledger_entry_hash=ledger_entry_hash.hex(),
        )


class AttestationRejectionReason(str, Enum):
    """Per-item rejection reasons for ``POST /snapshots/{id}/attestations``.

    Narrow set on purpose — every code is paired with a deterministic check
    in :func:`pke_backend.services.attestations.create_attestations_batch`,
    so clients can branch on the reason without parsing free-form text.
    """

    SNAPSHOT_MISMATCH = "snapshot_mismatch"
    SIGNATURE_INVALID = "signature_invalid"
    DUPLICATE_WITNESS_KEY = "duplicate_witness_key"
    VERSION_UNSUPPORTED = "version_unsupported"


class AttestationBatchRequest(BaseModel):
    """``POST /snapshots/{id}/attestations`` request envelope.

    Wraps the capturer's batch of witness attestations. The 50-item cap
    fires at the Pydantic layer (``max_length=MAX_BATCH_ATTESTATIONS``) so
    an over-cap upload is rejected with 422 ``invalid_payload`` before any
    signature verification work runs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    attestations: Annotated[
        list[WitnessAttestationIn],
        Field(min_length=1, max_length=MAX_BATCH_ATTESTATIONS),
    ]


class AcceptedAttestation(BaseModel):
    """Per-item entry in the batch response's ``accepted`` list.

    ``index`` is the 0-based position in the request body. ``ledger_entry_hash``
    is base64url-encoded so the value round-trips with the other POST
    envelopes in this service (HLAM-79 reports, HLAM-139 snapshots).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int
    witness_signing_public_key: str
    ledger_entry_id: uuid.UUID
    ledger_entry_hash: str


class RejectedAttestation(BaseModel):
    """Per-item entry in the batch response's ``rejected`` list.

    Carries the request-position index, the witness public key (base64url),
    and the rejection reason. The failing item's ``witness_signature`` and
    other binary fields are deliberately **not** echoed back to keep the
    response free of input bytes a client might mishandle in logs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int
    witness_signing_public_key: str
    reason: AttestationRejectionReason


class AttestationBatchResponse(BaseModel):
    """``POST /snapshots/{id}/attestations`` response envelope.

    Each request item shows up in exactly one of ``accepted`` / ``rejected``,
    preserving the request order (``index`` is the join key). The endpoint
    always returns 201; clients inspect the two lists to decide whether to
    retry individual items.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: uuid.UUID
    accepted: list[AcceptedAttestation]
    rejected: list[RejectedAttestation]


class WitnessAttestationListResponse(BaseModel):
    """GET /snapshots/{id}/attestations response envelope (HLAM-70).

    Always returns a list (possibly empty); the envelope leaves room for
    pagination metadata if the MVP 500-row cap is ever lifted.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    attestations: list[WitnessAttestationOut]
