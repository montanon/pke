"""Create key_grants table (HLAM-72).

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-17

Mirrors the ORM in :mod:`pke_backend.models.key_grant`. The composite UNIQUE
on ``(snapshot_id, recipient_encryption_public_key)`` enforces the protocol
invariant that a given recipient receives at most one wrapped key per
snapshot in MVP. ``snapshot_id`` carries a FK to ``snapshots(snapshot_id)``
with ``ON DELETE RESTRICT`` so cascading a snapshot delete cannot silently
drop the custody trail's grant rows.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "key_grants",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("grant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("recipient_encryption_public_key", sa.Text(), nullable=False),
        sa.Column("wrapped_snapshot_key", sa.LargeBinary(), nullable=False),
        sa.Column("wrapping_algorithm", sa.String(length=64), nullable=False),
        sa.Column("granted_by_signing_public_key", sa.Text(), nullable=False),
        sa.Column(
            "grant_timestamp",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
        ),
        sa.Column("grant_signature", sa.LargeBinary(), nullable=False),
        sa.Column(
            "version",
            sa.String(length=16),
            server_default=sa.text("'0.1'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("grant_id", name="uq_key_grants_grant_id"),
        sa.UniqueConstraint(
            "snapshot_id",
            "recipient_encryption_public_key",
            name="uq_key_grants_snapshot_recipient",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["snapshots.snapshot_id"],
            name="fk_key_grants_snapshot_id",
            ondelete="RESTRICT",
        ),
    )

    op.create_index(
        "ix_key_grants_snapshot_id",
        "key_grants",
        ["snapshot_id"],
    )
    op.create_index(
        "ix_key_grants_recipient_encryption_public_key",
        "key_grants",
        ["recipient_encryption_public_key"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_key_grants_recipient_encryption_public_key",
        table_name="key_grants",
    )
    op.drop_index("ix_key_grants_snapshot_id", table_name="key_grants")
    op.drop_table("key_grants")
