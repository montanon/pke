"""Integration tests for ``require_user`` + ``UnauthenticatedError`` (HLAM-122 S7).

Exercises every rejection path against a tiny in-test FastAPI app that
mounts a single ``Depends(require_user)`` route and overrides
``get_session`` to use the test engine.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from pke_backend.config import get_settings
from pke_backend.db import get_session
from pke_backend.models import Session, User
from pke_backend.security.dependencies import require_user
from pke_backend.security.errors import UnauthenticatedError, unauthenticated_handler

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"


def _alembic_config() -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", get_settings().DATABASE_URL)
    return cfg


async def _alembic_upgrade(target: str = "head") -> None:
    await asyncio.to_thread(command.upgrade, _alembic_config(), target)


async def _alembic_downgrade(target: str = "base") -> None:
    await asyncio.to_thread(command.downgrade, _alembic_config(), target)


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(get_settings().DATABASE_URL)
    try:
        async with eng.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        await eng.dispose()
        pytest.skip(f"postgres not reachable: {exc}")
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture(autouse=True)
async def _reset_db(engine: AsyncEngine) -> AsyncIterator[None]:
    await _alembic_downgrade()
    await _alembic_upgrade()
    yield
    await _alembic_downgrade()


@pytest.fixture
def app(engine: AsyncEngine) -> FastAPI:
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override_session() -> AsyncIterator:
        async with factory() as s:
            yield s

    test_app = FastAPI()
    test_app.add_exception_handler(UnauthenticatedError, unauthenticated_handler)
    test_app.dependency_overrides[get_session] = override_session

    @test_app.get("/protected")
    async def protected(user: Annotated[User, Depends(require_user)]) -> dict[str, str]:
        return {"user_id": str(user.user_id), "username": user.username}

    return test_app


@pytest.fixture
async def seeded(engine: AsyncEngine) -> tuple[User, Session]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        u = User(username="alice", password_hash="$argon2id$dummy")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        sess = Session(user_id=u.user_id, token=secrets.token_urlsafe(32))
        s.add(sess)
        await s.commit()
        await s.refresh(sess)
        return u, sess


async def _get(app: FastAPI, headers: dict[str, str] | None = None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get("/protected", headers=headers or {})


def _assert_uniform_401(resp: httpx.Response) -> None:
    assert resp.status_code == 401
    body = resp.json()
    assert body == {"error": {"code": "unauthenticated", "message": "Authentication required."}}


# --- AC1: happy path ---------------------------------------------------


async def test_valid_bearer_returns_user(app: FastAPI, seeded: tuple[User, Session]) -> None:
    user, sess = seeded
    resp = await _get(app, {"Authorization": f"Bearer {sess.token}"})
    assert resp.status_code == 200
    assert resp.json() == {"user_id": str(user.user_id), "username": user.username}


# --- AC2: missing header ----------------------------------------------


async def test_missing_authorization_header_returns_401(app: FastAPI) -> None:
    _assert_uniform_401(await _get(app))


# --- AC3: wrong scheme ------------------------------------------------


async def test_basic_scheme_returns_401(app: FastAPI) -> None:
    _assert_uniform_401(await _get(app, {"Authorization": "Basic dXNlcjpwYXNz"}))


# --- AC4: bearer no token ---------------------------------------------


async def test_bearer_without_token_returns_401(app: FastAPI) -> None:
    _assert_uniform_401(await _get(app, {"Authorization": "Bearer "}))


async def test_bearer_with_whitespace_only_returns_401(app: FastAPI) -> None:
    _assert_uniform_401(await _get(app, {"Authorization": "Bearer    "}))


# --- AC5: unknown token -----------------------------------------------


async def test_unknown_token_returns_401(app: FastAPI) -> None:
    _assert_uniform_401(await _get(app, {"Authorization": f"Bearer {secrets.token_urlsafe(32)}"}))


# --- AC6: revoked session --------------------------------------------


async def test_revoked_session_returns_401(
    app: FastAPI,
    engine: AsyncEngine,
    seeded: tuple[User, Session],
) -> None:
    _, sess = seeded
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        await s.execute(text("DELETE FROM sessions WHERE token = :t").bindparams(t=sess.token))
        await s.commit()
    _assert_uniform_401(await _get(app, {"Authorization": f"Bearer {sess.token}"}))


# --- AC7: consistent shape across calls -------------------------------


async def test_401_shape_is_uniform_across_rejection_paths(app: FastAPI) -> None:
    for headers in [
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": "bearer abc"},
        {"Authorization": f"Bearer {secrets.token_urlsafe(32)}"},
    ]:
        _assert_uniform_401(await _get(app, headers))


# --- Edge: whitespace around the token --------------------------------


async def test_token_is_stripped(app: FastAPI, seeded: tuple[User, Session]) -> None:
    _, sess = seeded
    resp = await _get(app, {"Authorization": f"Bearer   {sess.token}   "})
    assert resp.status_code == 200


# --- Edge: case-sensitive scheme --------------------------------------


async def test_lowercase_scheme_returns_401(app: FastAPI, seeded: tuple[User, Session]) -> None:
    _, sess = seeded
    _assert_uniform_401(await _get(app, {"Authorization": f"bearer {sess.token}"}))


# Orphan-session (sessions row whose user_id has no matching users row) is
# prevented at the DB layer by the ``ON DELETE CASCADE`` FK on
# ``sessions.user_id``. The dependency still degrades to a 401 if it ever
# happens (defensive ``user is None`` branch), but the path is unreachable
# in steady state and not separately tested.
