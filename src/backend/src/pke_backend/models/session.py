"""``Session`` ORM model — opaque bearer token bound to a ``User`` row.

Per HLAM-122 S1: ``session_id`` UUID PK, ``user_id`` FK with ``ON DELETE
CASCADE``, a 256-bit random ``token`` stored in plaintext (already a secret;
no further hashing needed for the MVP), and a server-default ``created_at``.

No expiry column — sessions live until explicit logout deletes the row.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import DateTime, ForeignKey, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from pke_backend.db import Base


class Session(Base):
    __tablename__ = "sessions"

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    # The token is already a 256-bit random secret; treat the value as sensitive.
    token: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        # Deliberately omits token.
        return f"Session(session_id={self.session_id!r}, user_id={self.user_id!r})"
