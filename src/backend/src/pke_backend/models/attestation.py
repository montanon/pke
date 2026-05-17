"""WitnessAttestation ORM model + ``WITNESS_ATTESTATION_VERSION`` constant.

SQLAlchemy 2.0 mirror of ``src/shared/schemas/witness_attestation.json`` for
the persistence layer specified by HLAM-39 (Witness Attestation endpoint).
The composite UNIQUE on ``(snapshot_id, witness_signing_public_key)``
enforces the "same witness key already attested" reject condition from
``context/04_protocol_overview.md``.

The wire-only fields ``ciphertext_hash``, ``session_nonce``, and
``owner_signing_public_key`` are intentionally *not* stored here — they live
on the referenced ``snapshots`` row (HLAM-61), and the signed canonical
bytes are reconstructable by joining at verify time.

``proximity_claim`` is ``JSONB NOT NULL`` and stored as-is per the
"unexpected shape" edge case; F6 normalises/ignores unknown fields. Do not
add a CHECK constraint — Pydantic owns shape validation upstream.
``witness_signature`` is ``LargeBinary`` with no length constraint — the
64-byte P1363 length is application-enforced upstream by HLAM-2's verifier.

This module is the persistence shape only — signature verification,
canonical-bytes reconstruction, and ledger emission belong to the service
layer (HLAM-39 stories #3–5).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Final

from sqlalchemy import (
    BigInteger,
    ForeignKey,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.sql.sqltypes import TIMESTAMP

from pke_backend.db import Base

__all__ = ["WITNESS_ATTESTATION_VERSION", "WitnessAttestation"]

WITNESS_ATTESTATION_VERSION: Final[str] = "0.1"

_REPR_SIGNATURE_PREFIX_BYTES = 8


class WitnessAttestation(Base):
    __tablename__ = "witness_attestations"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "witness_signing_public_key",
            name="uq_witness_attestations_snapshot_witness",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "snapshots.snapshot_id",
            name="fk_witness_attestations_snapshot_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    witness_signing_public_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    witness_timestamp: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
    )
    transport: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    proximity_claim: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )
    witness_signature: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=WITNESS_ATTESTATION_VERSION,
        server_default=WITNESS_ATTESTATION_VERSION,
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        signature = self.witness_signature
        if signature:
            prefix = signature[:_REPR_SIGNATURE_PREFIX_BYTES].hex()
            signature_repr = f"{prefix}..."
        else:
            signature_repr = "<unset>"
        return (
            f"WitnessAttestation(id={self.id!r}, snapshot_id={self.snapshot_id!r}, witness_signature={signature_repr})"
        )
