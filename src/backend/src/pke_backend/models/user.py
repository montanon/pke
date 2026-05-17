"""``User`` ORM model — account row backing the bearer-auth session table.

Per HLAM-122 S1: server-side ``user_id`` UUID PK, unique case-folded
``username``, argon2id ``password_hash`` (PHC-formatted string), and a
server-default ``created_at`` timestamp. No email, display name, role, or
verification flag — those are explicitly out of scope for the MVP.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import DateTime, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from pke_backend.db import Base


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    username: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    # password_hash is a sensitive secret — never log, never serialize.
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        # Deliberately omits password_hash.
        return f"User(user_id={self.user_id!r}, username={self.username!r})"
