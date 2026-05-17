"""Snapshot persistence migration: snapshots table + replay-protection UNIQUE.

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-17

Mirrors the ORM in :mod:`pke_backend.models.snapshot` (HLAM-61). No ENUM
lifecycle here (unlike 0001) — the only PostgreSQL-specific types are
``UUID`` and ``JSONB``, which are managed inline by the column definitions.

The explicit ``ix_snapshots_owner_signing_public_key`` is intentional even
though the composite ``UNIQUE(owner_signing_public_key, session_nonce)`` btree
already serves leftmost-prefix lookups: it decouples the index lifecycle from
the constraint so a future relaxation of the UNIQUE wouldn't silently drop
the read-path index.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "snapshots",
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ciphertext_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("owner_signing_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("owner_encryption_public_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "capture_timestamp",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
        ),
        sa.Column("metadata_policy", postgresql.JSONB(), nullable=False),
        sa.Column("session_nonce", sa.LargeBinary(length=16), nullable=False),
        sa.Column("owner_signature", sa.LargeBinary(), nullable=False),
        sa.Column(
            "version",
            sa.String(length=16),
            server_default=sa.text("'0.1'"),
            nullable=False,
        ),
        sa.Column("blob_storage_uri", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint(
            "owner_signing_public_key",
            "session_nonce",
            name="uq_snapshots_owner_pk_session_nonce",
        ),
    )

    op.create_index(
        "ix_snapshots_owner_signing_public_key",
        "snapshots",
        ["owner_signing_public_key"],
    )
    op.create_index(
        "ix_snapshots_created_at",
        "snapshots",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_snapshots_created_at", table_name="snapshots")
    op.drop_index(
        "ix_snapshots_owner_signing_public_key",
        table_name="snapshots",
    )
    op.drop_table("snapshots")
