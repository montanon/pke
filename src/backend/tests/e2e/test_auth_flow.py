"""End-to-end tests for the bearer-auth surface (HLAM-122 S9).

Per-route assertions live in ``tests/api/test_auth_routes.py`` (S3–S6).
This module covers cross-cutting behavior:

* full ``register → login → me → logout → me-401`` flow on a single client,
* per-user token isolation (one user's logout does not invalidate another's),
* HTTP-layer wall-time parity between wrong-password and unknown-user paths,
* smoke that ``Depends(require_user)`` works on a route mounted at runtime
  (S8 will apply it to the real custody routers — that's blocked on HLAM-47).
"""

from __future__ import annotations

import asyncio
import secrets
import statistics
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from pke_backend.config import get_settings
from pke_backend.db import get_session
from pke_backend.main import create_app
from pke_backend.models import User
from pke_backend.security.dependencies import require_user

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
_PW = "supersecret-pw"  # pragma: allowlist secret


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
def app(engine: AsyncEngine):
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override_session() -> AsyncIterator:
        async with factory() as s:
            yield s

    fastapi_app = create_app()
    fastapi_app.dependency_overrides[get_session] = override_session

    @fastapi_app.get("/custody/_smoke")
    async def custody_smoke(user: Annotated[User, Depends(require_user)]) -> dict[str, str]:
        return {"as_user": user.username}

    return fastapi_app


def _client(app) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------- Full happy-path flow ----------------


async def test_full_register_login_me_logout_me_flow(app) -> None:
    async with _client(app) as c:
        reg = await c.post("/v1/auth/register", json={"username": "alice", "password": _PW})
        assert reg.status_code == 201
        reg_token = reg.json()["token"]

        # /me works with the register token.
        me1 = await c.get("/v1/auth/me", headers=_bearer(reg_token))
        assert me1.status_code == 200
        assert me1.json()["username"] == "alice"

        # Login issues a fresh token that's different from register's token.
        login = await c.post("/v1/auth/login", json={"username": "alice", "password": _PW})
        assert login.status_code == 200
        login_token = login.json()["token"]
        assert login_token != reg_token

        # Both tokens are valid concurrently.
        me_reg = await c.get("/v1/auth/me", headers=_bearer(reg_token))
        me_login = await c.get("/v1/auth/me", headers=_bearer(login_token))
        assert me_reg.status_code == 200
        assert me_login.status_code == 200

        # Logout invalidates only the bearer used, not the other token.
        logout = await c.post("/v1/auth/logout", headers=_bearer(reg_token))
        assert logout.status_code == 204
        assert (await c.get("/v1/auth/me", headers=_bearer(reg_token))).status_code == 401
        assert (await c.get("/v1/auth/me", headers=_bearer(login_token))).status_code == 200


# ---------------- Token scoping across users ----------------


async def test_token_scopes_to_owning_user(app) -> None:
    async with _client(app) as c:
        a = (await c.post("/v1/auth/register", json={"username": "alice", "password": _PW})).json()
        b = (await c.post("/v1/auth/register", json={"username": "bob", "password": _PW})).json()
        assert a["token"] != b["token"]

        me_a = await c.get("/v1/auth/me", headers=_bearer(a["token"]))
        me_b = await c.get("/v1/auth/me", headers=_bearer(b["token"]))
        assert me_a.json()["username"] == "alice"
        assert me_b.json()["username"] == "bob"

        # Logging out alice does not affect bob.
        await c.post("/v1/auth/logout", headers=_bearer(a["token"]))
        assert (await c.get("/v1/auth/me", headers=_bearer(a["token"]))).status_code == 401
        assert (await c.get("/v1/auth/me", headers=_bearer(b["token"]))).status_code == 200


# ---------------- Login timing parity at the HTTP layer ----------------


async def _mean_login_ms(c: httpx.AsyncClient, username: str, password: str, n: int = 4) -> float:
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        await c.post("/v1/auth/login", json={"username": username, "password": password})
        samples.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(samples)


async def test_login_wrong_pw_vs_unknown_user_wall_time_parity(app) -> None:
    async with _client(app) as c:
        await c.post("/v1/auth/register", json={"username": "real", "password": _PW})
        wrong_pw_mean = await _mean_login_ms(c, "real", "wrongpwxx")
        unknown_mean = await _mean_login_ms(c, "ghostuser", _PW)
    ratio = unknown_mean / wrong_pw_mean
    # Wide window — both paths must hit one argon2id verify. Order-of-magnitude
    # divergence would mean the dummy-hash code path was skipped (regression).
    assert 0.5 <= ratio <= 1.5, f"login timing parity off: wrong_pw={wrong_pw_mean:.1f}ms, unknown={unknown_mean:.1f}ms"


# ---------------- Bearer-protected synthetic custody route ----------------


async def test_protected_route_with_valid_token_returns_200(app) -> None:
    async with _client(app) as c:
        reg = await c.post("/v1/auth/register", json={"username": "carol", "password": _PW})
        resp = await c.get("/custody/_smoke", headers=_bearer(reg.json()["token"]))
    assert resp.status_code == 200
    assert resp.json() == {"as_user": "carol"}


async def test_protected_route_without_bearer_returns_401(app) -> None:
    async with _client(app) as c:
        resp = await c.get("/custody/_smoke")
    assert resp.status_code == 401
    assert resp.json() == {
        "error": {"code": "unauthenticated", "message": "Authentication required."},
    }


async def test_protected_route_with_unknown_bearer_returns_401(app) -> None:
    async with _client(app) as c:
        resp = await c.get(
            "/custody/_smoke",
            headers=_bearer(secrets.token_urlsafe(32)),
        )
    assert resp.status_code == 401
