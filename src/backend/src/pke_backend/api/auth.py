"""Public ``/v1/auth/*`` routes (HLAM-122 S3–S6).

Register, login, logout, and ``me``. Register and login are unauthenticated;
logout and ``me`` require a bearer token.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.db import get_session
from pke_backend.models import Session, User
from pke_backend.schemas.auth import (
    AuthResponse,
    LoginRequest,
    RegisterRequest,
    UserPublic,
)
from pke_backend.security.dependencies import require_session, require_user
from pke_backend.security.errors import (
    DuplicateUsernameError,
    InvalidCredentialsError,
)
from pke_backend.services.auth import DUMMY_HASH, verify_password
from pke_backend.services.sessions import (
    create_session,
    lookup_user_by_username,
    register_user,
)

router = APIRouter(prefix="/v1/auth", tags=["auth"])

SessionDep = Annotated[AsyncSession, Depends(get_session)]
UserDep = Annotated[User, Depends(require_user)]
BearerSessionDep = Annotated[Session, Depends(require_session)]


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=AuthResponse,
)
async def register(body: RegisterRequest, db: SessionDep) -> AuthResponse:
    try:
        user = await register_user(db, body.username, body.password)
        session = await create_session(db, user)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise DuplicateUsernameError from None
    return AuthResponse(
        token=session.token,
        user=UserPublic(user_id=user.user_id, username=user.username),
    )


@router.post("/login", response_model=AuthResponse)
async def login(body: LoginRequest, db: SessionDep) -> AuthResponse:
    user = await lookup_user_by_username(db, body.username)
    # Run argon2id verify on every path — DUMMY_HASH on the unknown-user
    # branch keeps wall-time indistinguishable from a wrong-password verify.
    if user is None:
        verify_password(body.password, DUMMY_HASH)
        raise InvalidCredentialsError
    if not verify_password(body.password, user.password_hash):
        raise InvalidCredentialsError
    session = await create_session(db, user)
    await db.commit()
    return AuthResponse(
        token=session.token,
        user=UserPublic(user_id=user.user_id, username=user.username),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(session: BearerSessionDep, db: SessionDep) -> Response:
    await db.delete(session)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserPublic)
async def me(user: UserDep) -> UserPublic:
    return UserPublic(user_id=user.user_id, username=user.username)
