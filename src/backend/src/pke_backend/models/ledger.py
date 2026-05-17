"""LedgerEntry ORM model + ``EventType`` enum.

SQLAlchemy 2.0 mirror of ``src/shared/schemas/ledger_entry.json`` and the
column spec in HLAM-37 (Custody Ledger primitive). ``EventType`` is re-exported
from :mod:`pke_backend.protocol.ledger` so values stay locked to the
protocol's 5-value set:

``SNAPSHOT_COMMITTED``, ``WITNESS_ATTESTED``, ``KEY_GRANTED``, ``REPORTED``,
``FROZEN``.

Genesis rows store SQL ``NULL`` in ``previous_entry_hash`` by design; the wire
form base64url-encodes 32 zero bytes per ``context/16_canonical_encoding.md``.

This module is the persistence shape only — chain construction, hashing, and
verification belong to the service layer (HLAM-37 stories #4–5).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Final

from sqlalchemy import (
    BigInteger,
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
from pke_backend.protocol.ledger import LedgerEventType

__all__ = ["EventType", "LEDGER_VERSION", "LedgerEntry"]

LEDGER_VERSION: Final[str] = "0.1"

EventType = LedgerEventType

_REPR_HASH_PREFIX_BYTES = 8


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    __table_args__ = (
        Index("ix_ledger_entries_snapshot_id", "snapshot_id"),
        Index("ix_ledger_entries_event_type", "event_type"),
        Index("ix_ledger_entries_entry_timestamp", "entry_timestamp"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )
    ledger_entry_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        unique=True,
        nullable=False,
    )
    event_type: Mapped[EventType] = mapped_column(
        SQLEnum(
            EventType,
            name="event_type",
            native_enum=True,
            create_type=True,
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )
    payload_hash: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        nullable=False,
    )
    previous_entry_hash: Mapped[bytes | None] = mapped_column(
        LargeBinary(32),
        nullable=True,
    )
    entry_timestamp: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    entry_hash: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        unique=True,
        nullable=False,
    )
    version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=LEDGER_VERSION,
        server_default=LEDGER_VERSION,
    )

    def __repr__(self) -> str:
        entry_hash = self.entry_hash
        if entry_hash:
            prefix = entry_hash[:_REPR_HASH_PREFIX_BYTES].hex()
            entry_hash_repr = f"{prefix}..."
        else:
            entry_hash_repr = "<unset>"
        return (
            f"LedgerEntry("
            f"id={self.id!r}, "
            f"event_type={self.event_type.value!r}, "
            f"snapshot_id={self.snapshot_id!r}, "
            f"entry_hash={entry_hash_repr}"
            f")"
        )
