"""HTTP request/response models for the FastAPI surface.

Distinct from `pke_backend.protocol`, which holds the on-the-wire protocol payload
models (the 5 JSON-Schema-mirrored types) — those flow through canonicalize + sign
and must not be confused with the API contract models that live here.

`KeyGrantIn` / `KeyGrantOut` back the `/key-grants` endpoint (HLAM-40) and bind
`canonical_body_bytes()` for granter-signature verification per HLAM-3
§Signed-body rule. `SnapshotCommitmentIn` / `SnapshotOut` back `/snapshots`
(HLAM-62) and `WitnessAttestationIn` / `WitnessAttestationOut` back
`/attestations` (HLAM-39); all three follow the same canonical-bytes pattern.
"""

from __future__ import annotations

from pke_backend.schemas.attestation import (
    ProximityClaim,
    WitnessAttestationIn,
    WitnessAttestationOut,
)
from pke_backend.schemas.key_grant import (
    ECDSA_P1363_SIGNATURE_BYTES,
    KEY_GRANT_VERSION,
    RECIPIENT_PUBLIC_KEY_BYTES,
    SIGNING_PUBLIC_KEY_BYTES,
    WRAPPED_SNAPSHOT_KEY_BYTES,
    WRAPPING_ALGORITHM_ALLOWLIST,
    KeyGrantIn,
    KeyGrantOut,
    PersistedKeyGrant,
)
from pke_backend.schemas.snapshot import (
    OWNER_SIGNING_PUBLIC_KEY_BYTES,
    SnapshotCommitmentIn,
    SnapshotOut,
)

__all__ = [
    "ECDSA_P1363_SIGNATURE_BYTES",
    "KEY_GRANT_VERSION",
    "OWNER_SIGNING_PUBLIC_KEY_BYTES",
    "RECIPIENT_PUBLIC_KEY_BYTES",
    "SIGNING_PUBLIC_KEY_BYTES",
    "WRAPPED_SNAPSHOT_KEY_BYTES",
    "WRAPPING_ALGORITHM_ALLOWLIST",
    "KeyGrantIn",
    "KeyGrantOut",
    "PersistedKeyGrant",
    "ProximityClaim",
    "SnapshotCommitmentIn",
    "SnapshotOut",
    "WitnessAttestationIn",
    "WitnessAttestationOut",
]
