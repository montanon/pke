"""Create witness_attestations table.

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-17

Mirrors the ORM in :mod:`pke_backend.models.attestation` (HLAM-67). Follows
0002 (``snapshots`` table, HLAM-61), which owns the foreign-key target
``snapshots.snapshot_id``.

The composite ``UniqueConstraint`` on ``(snapshot_id,
witness_signing_public_key)`` doubles as the listing-by-snapshot read index
(per the implementation note: add a separate ``created_at`` index only if
listings show N+1 behavior). No PostgreSQL ENUM lifecycle is required;
``transport`` is free-form ``VARCHAR(64)`` per the Story spec.

``witness_signing_public_key`` is stored as ``TEXT`` (base64url ASCII per
``context/16_canonical_encoding.md``). Under PG ≥13 the default UTF-8
encoding makes the UNIQUE B-tree comparison deterministic for ASCII
content; no ``COLLATE "C"`` clause is needed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "witness_attestations",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("witness_signing_public_key", sa.Text(), nullable=False),
        sa.Column(
            "witness_timestamp",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
        ),
        sa.Column("transport", sa.String(length=64), nullable=False),
        sa.Column(
            "proximity_claim",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("witness_signature", sa.LargeBinary(), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["snapshots.snapshot_id"],
            name="fk_witness_attestations_snapshot_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "snapshot_id",
            "witness_signing_public_key",
            name="uq_witness_attestations_snapshot_witness",
        ),
    )


def downgrade() -> None:
    op.drop_table("witness_attestations")
