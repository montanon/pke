"""End-to-end tests for ``/v1/auth/*`` (HLAM-122 S3–S6).

One module covers register, login, logout, and ``me``. Each test owns a
fresh DB schema via the autouse ``_reset_db`` fixture, and the FastAPI app
is built per-test with ``get_session`` overridden to bind to the test
engine.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from pke_backend.config import get_settings
from pke_backend.db import get_session
from pke_backend.main import create_app
from pke_backend.models import Session, User

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
def app(engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override_session() -> AsyncIterator:
        async with factory() as s:
            yield s

    fastapi_app = create_app()
    fastapi_app.dependency_overrides[get_session] = override_session
    return fastapi_app  # type: ignore[return-value]  # used as ASGI app, not iterated


async def _client(app) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------- register ----------------


async def test_register_returns_201_and_token(app) -> None:
    async for c in _client(app):
        resp = await c.post(
            "/v1/auth/register",
            json={"username": "alice", "password": "correct horse"},  # pragma: allowlist secret
        )
    assert resp.status_code == 201
    body = resp.json()
    assert "token" in body
    assert body["user"]["username"] == "alice"
    assert "password_hash" not in body and "password" not in body


async def test_register_persists_user_and_session(app, engine: AsyncEngine) -> None:
    async for c in _client(app):
        resp = await c.post(
            "/v1/auth/register",
            json={"username": "bob", "password": "supersecret"},  # pragma: allowlist secret
        )
    assert resp.status_code == 201
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        user = await s.scalar(select(User).where(User.username == "bob"))
        assert user is not None
        session = await s.scalar(select(Session).where(Session.user_id == user.user_id))
        assert session is not None and session.token == resp.json()["token"]


async def test_register_duplicate_username_returns_409(app) -> None:
    async for c in _client(app):
        await c.post(
            "/v1/auth/register",
            json={"username": "carol", "password": "supersecret"},  # pragma: allowlist secret
        )
        resp = await c.post(
            "/v1/auth/register",
            json={"username": "carol", "password": "differentpw"},  # pragma: allowlist secret
        )
    assert resp.status_code == 409
    assert resp.json() == {
        "error": {"code": "duplicate_username", "message": "Username already taken."},
    }


async def test_register_case_folds_username(app) -> None:
    async for c in _client(app):
        await c.post(
            "/v1/auth/register",
            json={"username": "Dan", "password": "supersecret"},  # pragma: allowlist secret
        )
        resp = await c.post(
            "/v1/auth/register",
            json={"username": "DAN", "password": "supersecret"},  # pragma: allowlist secret
        )
    assert resp.status_code == 409


@pytest.mark.parametrize(
    ("username", "password", "expected"),
    [
        ("ab", "supersecret", 422),  # too short username
        ("a" * 33, "supersecret", 422),  # too long username
        ("BadChar!", "supersecret", 422),  # invalid char after case-fold
        ("ok_user", "short", 422),  # password < 8
        ("ok_user", "x" * 1025, 422),  # password > 1024
    ],
)
async def test_register_validation_errors_return_422(app, username, password, expected) -> None:
    async for c in _client(app):
        resp = await c.post(
            "/v1/auth/register",
            json={"username": username, "password": password},
        )
    assert resp.status_code == expected


# ---------------- login ----------------


async def test_login_valid_credentials_returns_200_with_new_session(app, engine: AsyncEngine) -> None:
    async for c in _client(app):
        reg = await c.post(
            "/v1/auth/register",
            json={"username": "erin", "password": "supersecret"},  # pragma: allowlist secret
        )
        login = await c.post(
            "/v1/auth/login",
            json={"username": "erin", "password": "supersecret"},  # pragma: allowlist secret
        )
    assert login.status_code == 200
    assert login.json()["user"]["username"] == "erin"
    assert login.json()["token"] != reg.json()["token"]
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        count = await s.scalar(text("SELECT COUNT(*) FROM sessions"))
        assert count == 2


async def test_login_wrong_password_returns_401_invalid_credentials(app) -> None:
    async for c in _client(app):
        await c.post(
            "/v1/auth/register",
            json={"username": "frank", "password": "supersecret"},  # pragma: allowlist secret
        )
        resp = await c.post(
            "/v1/auth/login",
            json={"username": "frank", "password": "wrongpwxx"},  # pragma: allowlist secret
        )
    assert resp.status_code == 401
    assert resp.json() == {
        "error": {"code": "invalid_credentials", "message": "Invalid credentials."},
    }


async def test_login_unknown_username_returns_same_401_shape(app) -> None:
    async for c in _client(app):
        resp = await c.post(
            "/v1/auth/login",
            json={"username": "ghost", "password": "supersecret"},  # pragma: allowlist secret
        )
    assert resp.status_code == 401
    assert resp.json() == {
        "error": {"code": "invalid_credentials", "message": "Invalid credentials."},
    }


# ---------------- logout ----------------


async def test_logout_deletes_session_and_returns_204(app, engine: AsyncEngine) -> None:
    async for c in _client(app):
        reg = await c.post(
            "/v1/auth/register",
            json={"username": "henry", "password": "supersecret"},  # pragma: allowlist secret
        )
        token = reg.json()["token"]
        resp = await c.post("/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        # Same bearer can't be reused.
        me_resp = await c.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 204
    assert me_resp.status_code == 401
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        count = await s.scalar(text("SELECT COUNT(*) FROM sessions"))
        assert count == 0


async def test_logout_without_bearer_returns_401(app) -> None:
    async for c in _client(app):
        resp = await c.post("/v1/auth/logout")
    assert resp.status_code == 401


# ---------------- me ----------------


async def test_me_returns_user_id_and_username(app) -> None:
    async for c in _client(app):
        reg = await c.post(
            "/v1/auth/register",
            json={"username": "ivy", "password": "supersecret"},  # pragma: allowlist secret
        )
        token = reg.json()["token"]
        resp = await c.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"user_id", "username"}
    assert body["username"] == "ivy"


async def test_me_without_bearer_returns_401(app) -> None:
    async for c in _client(app):
        resp = await c.get("/v1/auth/me")
    assert resp.status_code == 401


# ---------------- OpenAPI does not expose password_hash ----------------


async def test_openapi_schema_never_exposes_password_hash(app) -> None:
    async for c in _client(app):
        resp = await c.get("/openapi.json")
    assert resp.status_code == 200
    schema_text = resp.text
    assert "password_hash" not in schema_text
