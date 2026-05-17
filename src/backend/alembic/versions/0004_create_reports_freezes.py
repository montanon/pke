"""Reports + freezes tables and the ``reason_category`` ENUM (HLAM-77).

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-17

Mirrors the ORMs in :mod:`pke_backend.models.report` and
:mod:`pke_backend.models.freeze`. The ``reason_category`` ENUM is created
and dropped explicitly so partial-failure retries are predictable; the
column references it with ``create_type=False`` to keep the type lifecycle
decoupled from ``create_table`` (same pattern as 0001's ``event_type``).

This revision takes the 0004 slot because HLAM-72's key-grants migration
had not landed on dev when this story merged. HLAM-72 will chain on as
0005 with ``down_revision = "0004"`` when it rebases.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from pke_backend.protocol.report_action import ReasonCategory

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _reason_category_enum() -> postgresql.ENUM:
    return postgresql.ENUM(
        *(member.value for member in ReasonCategory),
        name="reason_category",
        create_type=False,
    )


def upgrade() -> None:
    bind = op.get_bind()
    reason_category_enum = _reason_category_enum()
    reason_category_enum.create(bind, checkfirst=True)

    op.create_table(
        "reports",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reason_category", reason_category_enum, nullable=False),
        sa.Column(
            "reported_by_signing_public_key",
            sa.LargeBinary(),
            nullable=False,
        ),
        sa.Column(
            "report_status",
            sa.String(length=32),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("report_signature", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_id", name="uq_reports_report_id"),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["snapshots.snapshot_id"],
            name="fk_reports_snapshot_id",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_reports_snapshot_id",
        "reports",
        ["snapshot_id"],
    )

    op.create_table(
        "freezes",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("freeze_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "triggered_by_report_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "freeze_status",
            sa.String(length=32),
            server_default=sa.text("'active'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("freeze_signature", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("freeze_id", name="uq_freezes_freeze_id"),
        sa.UniqueConstraint("snapshot_id", name="uq_freezes_snapshot_id"),
        sa.ForeignKeyConstraint(
            ["triggered_by_report_id"],
            ["reports.report_id"],
            name="fk_freezes_triggered_by_report_id",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_freezes_snapshot_id",
        "freezes",
        ["snapshot_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_freezes_snapshot_id", table_name="freezes")
    op.drop_table("freezes")

    op.drop_index("ix_reports_snapshot_id", table_name="reports")
    op.drop_table("reports")

    bind = op.get_bind()
    _reason_category_enum().drop(bind, checkfirst=True)
