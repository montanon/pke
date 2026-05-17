"""Initial migration: ledger_entries table + event_type ENUM.

Revision ID: 0001
Revises:
Create Date: 2026-05-17

Mirrors the ORM in :mod:`pke_backend.models.ledger` (HLAM-53). The
``event_type`` ENUM is created and dropped explicitly so partial-failure
retries are predictable; the column references it with ``create_type=False``
to keep the type lifecycle decoupled from ``create_table``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from pke_backend.protocol.ledger import LedgerEventType

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _event_type_enum() -> postgresql.ENUM:
    return postgresql.ENUM(
        *(member.value for member in LedgerEventType),
        name="event_type",
        create_type=False,
    )


def upgrade() -> None:
    bind = op.get_bind()
    event_type_enum = _event_type_enum()
    event_type_enum.create(bind, checkfirst=True)

    op.create_table(
        "ledger_entries",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ledger_entry_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", event_type_enum, nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("payload_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("previous_entry_hash", sa.LargeBinary(length=32), nullable=True),
        sa.Column(
            "entry_timestamp",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("entry_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column(
            "version",
            sa.String(length=16),
            server_default=sa.text("'0.1'"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ledger_entry_id",
            name="uq_ledger_entries_ledger_entry_id",
        ),
        sa.UniqueConstraint(
            "entry_hash",
            name="uq_ledger_entries_entry_hash",
        ),
    )

    op.create_index(
        "ix_ledger_entries_snapshot_id",
        "ledger_entries",
        ["snapshot_id"],
    )
    op.create_index(
        "ix_ledger_entries_event_type",
        "ledger_entries",
        ["event_type"],
    )
    op.create_index(
        "ix_ledger_entries_entry_timestamp",
        "ledger_entries",
        ["entry_timestamp"],
    )


def downgrade() -> None:
    op.drop_index("ix_ledger_entries_entry_timestamp", table_name="ledger_entries")
    op.drop_index("ix_ledger_entries_event_type", table_name="ledger_entries")
    op.drop_index("ix_ledger_entries_snapshot_id", table_name="ledger_entries")
    op.drop_table("ledger_entries")

    bind = op.get_bind()
    _event_type_enum().drop(bind, checkfirst=True)
