"""KeyGrant ORM model.

SQLAlchemy 2.0 mirror of ``src/shared/schemas/key_grant.json`` and the
``KeyGrant`` row in HLAM-40 (Key Grant endpoint) Technical Surface.

The ``wrapped_snapshot_key`` column stores opaque AES-GCM ciphertext: 12-byte
nonce + 32-byte ciphertext + 16-byte tag (60 bytes total per HLAM-3). The
backend never unwraps; length is enforced at the API layer.

``snapshot_id`` is a FK to ``snapshots(snapshot_id)`` with ``ON DELETE
RESTRICT`` — a snapshot row cannot be removed while grants still reference
it, so the custody trail's grant rows never become orphans. The composite
UNIQUE ``(snapshot_id, recipient_encryption_public_key)`` enforces the
protocol invariant that a single recipient receives at most one wrapped key
per snapshot in MVP.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Final

from sqlalchemy import (
    BigInteger,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.sql.sqltypes import TIMESTAMP

from pke_backend.db import Base

__all__ = ["KEY_GRANT_VERSION", "KeyGrant"]

KEY_GRANT_VERSION: Final[str] = "0.1"

_REPR_KEY_PREFIX_BYTES = 8
_REPR_RECIPIENT_PREFIX_CHARS = 12


class KeyGrant(Base):
    __tablename__ = "key_grants"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "recipient_encryption_public_key",
            name="uq_key_grants_snapshot_recipient",
        ),
        Index("ix_key_grants_snapshot_id", "snapshot_id"),
        Index(
            "ix_key_grants_recipient_encryption_public_key",
            "recipient_encryption_public_key",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    grant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        unique=True,
        nullable=False,
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "snapshots.snapshot_id",
            name="fk_key_grants_snapshot_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    recipient_encryption_public_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    wrapped_snapshot_key: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    wrapping_algorithm: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    granted_by_signing_public_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    grant_timestamp: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
    )
    grant_signature: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=KEY_GRANT_VERSION,
        server_default=KEY_GRANT_VERSION,
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        wrapped = self.wrapped_snapshot_key
        if wrapped:
            wrapped_repr = f"{wrapped[:_REPR_KEY_PREFIX_BYTES].hex()}..."
        else:
            wrapped_repr = "<unset>"
        recipient = self.recipient_encryption_public_key
        if recipient:
            recipient_repr = f"{recipient[:_REPR_RECIPIENT_PREFIX_CHARS]}..."
        else:
            recipient_repr = "<unset>"
        return (
            f"KeyGrant("
            f"id={self.id!r}, "
            f"grant_id={self.grant_id!r}, "
            f"snapshot_id={self.snapshot_id!r}, "
            f"recipient={recipient_repr}, "
            f"wrapped_snapshot_key={wrapped_repr}"
            f")"
        )
