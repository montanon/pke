"""HTTP request/response models for the FastAPI surface.

Distinct from `pke_backend.protocol`, which holds the on-the-wire protocol payload
models (the 5 JSON-Schema-mirrored types) — those flow through canonicalize + sign
and must not be confused with the API contract models that live here.
"""

from __future__ import annotations

from pke_backend.schemas.attestation import (
    ProximityClaim,
    WitnessAttestationIn,
    WitnessAttestationOut,
)
from pke_backend.schemas.snapshot import (
    OWNER_SIGNING_PUBLIC_KEY_BYTES,
    SnapshotCommitmentIn,
    SnapshotOut,
)

__all__ = [
    "OWNER_SIGNING_PUBLIC_KEY_BYTES",
    "ProximityClaim",
    "SnapshotCommitmentIn",
    "SnapshotOut",
    "WitnessAttestationIn",
    "WitnessAttestationOut",
]
