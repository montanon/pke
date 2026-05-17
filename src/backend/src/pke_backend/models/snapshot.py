"""Snapshot ORM model — persistence shape for the snapshot commitment.

SQLAlchemy 2.0 mirror of ``src/shared/schemas/snapshot_commitment.json`` and
the column spec in HLAM-61 / HLAM-38 (Snapshot Commitment endpoint + Encrypted
Blob Storage).

``snapshot_id`` is the natural primary key: every downstream table (witness
attestations, key grants, reports, freezes, verification reports) joins by
``snapshot_id``, and clients supply the value as part of the commitment so the
backend never has to generate a surrogate.

Replay protection lives at the database level via
``UNIQUE(owner_signing_public_key, session_nonce)`` — the same owner cannot
reuse a session nonce across snapshots. ``IntegrityError`` surfaces to the
service layer, which decides whether to read the existing row (legitimate
retry) or reject (true replay).

This module is the persistence shape only — request validation, length guards
for ``ciphertext_hash`` / ``session_nonce``, blob upload, and ledger chaining
all belong to the service layer.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Final

from sqlalchemy import (
    Index,
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

__all__ = [
    "CIPHERTEXT_HASH_BYTES",
    "SESSION_NONCE_BYTES",
    "SNAPSHOT_VERSION",
    "Snapshot",
]

SNAPSHOT_VERSION: Final[str] = "0.1"
SESSION_NONCE_BYTES: Final[int] = 16
CIPHERTEXT_HASH_BYTES: Final[int] = 32

_REPR_HASH_PREFIX_BYTES = 8


class Snapshot(Base):
    __tablename__ = "snapshots"
    __table_args__ = (
        UniqueConstraint(
            "owner_signing_public_key",
            "session_nonce",
            name="uq_snapshots_owner_pk_session_nonce",
        ),
        Index(
            "ix_snapshots_owner_signing_public_key",
            "owner_signing_public_key",
        ),
        Index("ix_snapshots_created_at", "created_at"),
    )

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
    )
    ciphertext_hash: Mapped[bytes] = mapped_column(
        LargeBinary(CIPHERTEXT_HASH_BYTES),
        nullable=False,
    )
    owner_signing_public_key: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    owner_encryption_public_key: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    capture_timestamp: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
    )
    metadata_policy: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )
    session_nonce: Mapped[bytes] = mapped_column(
        LargeBinary(SESSION_NONCE_BYTES),
        nullable=False,
    )
    owner_signature: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=SNAPSHOT_VERSION,
        server_default=SNAPSHOT_VERSION,
    )
    blob_storage_uri: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        ciphertext_hash = self.ciphertext_hash
        if ciphertext_hash:
            prefix = ciphertext_hash[:_REPR_HASH_PREFIX_BYTES].hex()
            hash_repr = f"{prefix}..."
        else:
            hash_repr = "<unset>"
        return f"Snapshot(snapshot_id={self.snapshot_id!r}, ciphertext_hash={hash_repr}, version={self.version!r})"
