"""FastAPI dependencies for bearer-token authentication (HLAM-122 S7).

``require_user`` is the single entry point every protected route uses.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.db import get_session
from pke_backend.models import Session, User
from pke_backend.security.errors import UnauthenticatedError

_BEARER_PREFIX = "Bearer "

SessionDep = Annotated[AsyncSession, Depends(get_session)]


def _extract_bearer(request: Request) -> str:
    header = request.headers.get("Authorization")
    if not header or not header.startswith(_BEARER_PREFIX):
        raise UnauthenticatedError
    token = header[len(_BEARER_PREFIX) :].strip()
    if not token:
        raise UnauthenticatedError
    return token


async def require_session(
    request: Request,
    db: SessionDep,
) -> Session:
    """Return the active ``Session`` row for the request's bearer token.

    Raises :class:`UnauthenticatedError` on any rejection path. Routes
    that only need the user should use :func:`require_user`; routes that
    need to mutate the session row directly (e.g. logout) take this.
    """
    token = _extract_bearer(request)
    session = await db.scalar(select(Session).where(Session.token == token))
    if session is None:
        raise UnauthenticatedError
    return session


async def require_user(
    request: Request,
    db: SessionDep,
) -> User:
    """Return the ``User`` bound to the request's bearer token."""
    session = await require_session(request, db)
    user = await db.get(User, session.user_id)
    if user is None:
        # Session row outlived its user — should not happen under the
        # ON DELETE CASCADE FK, but treat defensively as 401.
        raise UnauthenticatedError
    return user
