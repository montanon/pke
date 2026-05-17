"""Persistence helpers for the auth surface (HLAM-122 S3–S6).

Pure functions over an ``AsyncSession``. No global state, no caching.
Each route owns its own commit boundary — these helpers add the row to
the session and return the persisted entity but do not commit so the
caller can compose multi-step operations atomically.
"""

from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.models import Session, User
from pke_backend.services.auth import hash_password

_TOKEN_BYTES = 32


def _new_token() -> str:
    """Return a 256-bit URL-safe random token (RFC 6750 opaque bearer)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


async def register_user(db: AsyncSession, username: str, password: str) -> User:
    """Persist a new ``User`` with the password hashed at our argon2id params."""
    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    await db.flush()
    return user


async def lookup_user_by_username(db: AsyncSession, username: str) -> User | None:
    result: User | None = await db.scalar(select(User).where(User.username == username))
    return result


async def create_session(db: AsyncSession, user: User) -> Session:
    session = Session(user_id=user.user_id, token=_new_token())
    db.add(session)
    await db.flush()
    return session


async def delete_session_by_token(db: AsyncSession, token: str) -> None:
    sess = await db.scalar(select(Session).where(Session.token == token))
    if sess is not None:
        await db.delete(sess)
