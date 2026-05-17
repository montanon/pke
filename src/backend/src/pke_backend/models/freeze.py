"""Freeze ORM model.

SQLAlchemy 2.0 mirror of ``src/shared/schemas/freeze.json`` and the column
spec in HLAM-77. A snapshot can be frozen at most once, enforced by a
UNIQUE constraint on ``freezes.snapshot_id``. Every freeze cites the report
that triggered it via a foreign key with ``ON DELETE RESTRICT`` — orphan
freezes are blocked at the database level.

The persistence shape only; signature verification, ledger anchoring, and
freeze-aware key-grant blocking belong to the service layer (HLAM-79, HLAM-80).
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
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.sql.sqltypes import TIMESTAMP

from pke_backend.db import Base
from pke_backend.protocol.freeze import FREEZE_VERSION

__all__ = ["FREEZE_VERSION", "Freeze"]

_REPR_UUID_PREFIX_CHARS = 8
_FREEZE_STATUS_ACTIVE: Final[str] = "active"


class Freeze(Base):
    __tablename__ = "freezes"
    __table_args__ = (
        UniqueConstraint("snapshot_id", name="uq_freezes_snapshot_id"),
        Index("ix_freezes_snapshot_id", "snapshot_id"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    freeze_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        unique=True,
        nullable=False,
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )
    triggered_by_report_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "reports.report_id",
            name="fk_freezes_triggered_by_report_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    freeze_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=_FREEZE_STATUS_ACTIVE,
        server_default=_FREEZE_STATUS_ACTIVE,
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    freeze_signature: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    def __repr__(self) -> str:
        freeze_id = self.freeze_id
        if freeze_id:
            freeze_id_repr = f"{freeze_id.hex[:_REPR_UUID_PREFIX_CHARS]}..."
        else:
            freeze_id_repr = "<unset>"
        triggered_by = self.triggered_by_report_id
        if triggered_by:
            triggered_by_repr = f"{triggered_by.hex[:_REPR_UUID_PREFIX_CHARS]}..."
        else:
            triggered_by_repr = "<unset>"
        return (
            f"Freeze("
            f"id={self.id!r}, "
            f"snapshot_id={self.snapshot_id!r}, "
            f"freeze_id={freeze_id_repr}, "
            f"triggered_by_report_id={triggered_by_repr}"
            f")"
        )
