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


async def require_user(
    request: Request,
    db: SessionDep,
) -> User:
    """Return the ``User`` bound to the request's bearer token.

    Raises :class:`UnauthenticatedError` on any rejection path — missing
    header, wrong scheme (case-sensitive per RFC 6750 §2.1), empty token,
    unknown token, or revoked session. The exception handler in
    :mod:`pke_backend.security.errors` translates that to the uniform 401.
    """
    header = request.headers.get("Authorization")
    if not header or not header.startswith(_BEARER_PREFIX):
        raise UnauthenticatedError
    token = header[len(_BEARER_PREFIX) :].strip()
    if not token:
        raise UnauthenticatedError

    session = await db.scalar(select(Session).where(Session.token == token))
    if session is None:
        raise UnauthenticatedError

    user = await db.get(User, session.user_id)
    if user is None:
        # Session row outlived its user — should not happen under the
        # ON DELETE CASCADE FK, but treat defensively as 401.
        raise UnauthenticatedError
    return user
