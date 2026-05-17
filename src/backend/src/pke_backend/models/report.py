"""Report ORM model + ``ReasonCategory`` enum.

SQLAlchemy 2.0 mirror of ``src/shared/schemas/report.json`` and the
column spec in HLAM-77. ``ReasonCategory`` is re-exported from
:mod:`pke_backend.protocol.report_action` so values stay locked to the
protocol's 4-value set:

``abuse_concern``, ``legal_request``, ``owner_request``, ``other``.

The persistence shape only; signature verification, ledger anchoring, and
authorization belong to the service layer (HLAM-79).
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
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.sql.sqltypes import TIMESTAMP

from pke_backend.db import Base
from pke_backend.protocol.report_action import REPORT_VERSION, ReasonCategory

__all__ = ["REPORT_VERSION", "ReasonCategory", "Report"]

_REPR_UUID_PREFIX_CHARS = 8
_REPORT_STATUS_PENDING: Final[str] = "pending"


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_snapshot_id", "snapshot_id"),)

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        unique=True,
        nullable=False,
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "snapshots.snapshot_id",
            name="fk_reports_snapshot_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    reason_category: Mapped[ReasonCategory] = mapped_column(
        SQLEnum(
            ReasonCategory,
            name="reason_category",
            native_enum=True,
            create_type=True,
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
    )
    reported_by_signing_public_key: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    report_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=_REPORT_STATUS_PENDING,
        server_default=_REPORT_STATUS_PENDING,
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    report_signature: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    def __repr__(self) -> str:
        report_id = self.report_id
        if report_id:
            report_id_repr = f"{report_id.hex[:_REPR_UUID_PREFIX_CHARS]}..."
        else:
            report_id_repr = "<unset>"
        return (
            f"Report("
            f"id={self.id!r}, "
            f"reason_category={self.reason_category.value!r}, "
            f"snapshot_id={self.snapshot_id!r}, "
            f"report_id={report_id_repr}"
            f")"
        )
