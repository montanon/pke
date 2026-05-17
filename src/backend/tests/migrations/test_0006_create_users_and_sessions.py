"""Integration tests for migration 0006_create_users_and_sessions (HLAM-122 S1)."""

from __future__ import annotations

import asyncio
import secrets
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from pke_backend.config import get_settings
from pke_backend.models import Session, User

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"

EXPECTED_USERS_COLUMNS: dict[str, bool] = {
    "user_id": False,
    "username": False,
    "password_hash": False,
    "created_at": False,
}

EXPECTED_SESSIONS_COLUMNS: dict[str, bool] = {
    "session_id": False,
    "user_id": False,
    "token": False,
    "created_at": False,
}


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
    yield
    await _alembic_downgrade()


async def _table_names(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda c: sa_inspect(c).get_table_names())


def _new_token() -> str:
    return secrets.token_urlsafe(32)


# --- Migration shape tests ----------------------------------------------


async def test_upgrade_creates_users_and_sessions_tables(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    names = await _table_names(engine)
    assert "users" in names
    assert "sessions" in names


async def test_users_columns_match_spec(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        cols = await conn.run_sync(lambda c: sa_inspect(c).get_columns("users"))
    by_name = {c["name"]: c for c in cols}
    assert set(by_name) == set(EXPECTED_USERS_COLUMNS)
    for name, nullable in EXPECTED_USERS_COLUMNS.items():
        assert by_name[name]["nullable"] is nullable, f"{name} nullability mismatch"
    assert by_name["user_id"]["default"] is not None
    assert by_name["created_at"]["default"] is not None


async def test_sessions_columns_match_spec(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        cols = await conn.run_sync(lambda c: sa_inspect(c).get_columns("sessions"))
    by_name = {c["name"]: c for c in cols}
    assert set(by_name) == set(EXPECTED_SESSIONS_COLUMNS)
    for name, nullable in EXPECTED_SESSIONS_COLUMNS.items():
        assert by_name[name]["nullable"] is nullable, f"{name} nullability mismatch"
    assert by_name["session_id"]["default"] is not None


async def test_users_username_is_unique(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        uniques = await conn.run_sync(
            lambda c: sa_inspect(c).get_unique_constraints("users"),
        )
    cols = {tuple(u["column_names"]) for u in uniques}
    assert ("username",) in cols


async def test_sessions_token_is_unique_and_user_fk_cascades(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    async with engine.connect() as conn:
        uniques = await conn.run_sync(
            lambda c: sa_inspect(c).get_unique_constraints("sessions"),
        )
        fks = await conn.run_sync(lambda c: sa_inspect(c).get_foreign_keys("sessions"))
    assert ("token",) in {tuple(u["column_names"]) for u in uniques}
    fk = next(fk for fk in fks if fk["referred_table"] == "users")
    assert fk["constrained_columns"] == ["user_id"]
    assert fk["options"].get("ondelete", "").upper() == "CASCADE"


async def test_downgrade_drops_both_tables(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    await _alembic_downgrade()
    names = await _table_names(engine)
    assert "users" not in names
    assert "sessions" not in names


# --- ORM behavior tests --------------------------------------------------


async def test_insert_user_and_session_via_orm(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        u = User(username="alice", password_hash="$argon2id$dummy")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        assert isinstance(u.user_id, uuid.UUID)
        assert u.created_at is not None

        sess = Session(user_id=u.user_id, token=_new_token())
        s.add(sess)
        await s.commit()
        await s.refresh(sess)
        assert isinstance(sess.session_id, uuid.UUID)


async def test_duplicate_username_raises_integrity_error(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        s.add(User(username="bob", password_hash="$argon2id$x"))
        await s.commit()
        s.add(User(username="bob", password_hash="$argon2id$y"))
        with pytest.raises(IntegrityError):
            await s.commit()
        await s.rollback()


async def test_duplicate_session_token_raises_integrity_error(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        u = User(username="carol", password_hash="$argon2id$z")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        token = _new_token()
        s.add(Session(user_id=u.user_id, token=token))
        await s.commit()
        s.add(Session(user_id=u.user_id, token=token))
        with pytest.raises(IntegrityError):
            await s.commit()
        await s.rollback()


async def test_session_cascade_on_user_delete(engine: AsyncEngine) -> None:
    await _alembic_upgrade()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        u = User(username="erin", password_hash="$argon2id$z")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        s.add(Session(user_id=u.user_id, token=_new_token()))
        s.add(Session(user_id=u.user_id, token=_new_token()))
        await s.commit()

        await s.delete(u)
        await s.commit()

        remaining = await s.scalar(
            text("SELECT COUNT(*) FROM sessions WHERE user_id = :uid").bindparams(uid=u.user_id),
        )
        assert remaining == 0


def test_user_repr_omits_password_hash() -> None:
    u = User(user_id=uuid.uuid4(), username="frank", password_hash="$argon2id$super-secret")
    rendered = repr(u)
    assert "super-secret" not in rendered
    assert "password_hash" not in rendered
    assert "frank" in rendered


def test_session_repr_omits_token() -> None:
    s = Session(session_id=uuid.uuid4(), user_id=uuid.uuid4(), token="super-secret-token")
    rendered = repr(s)
    assert "super-secret-token" not in rendered
    assert "token" not in rendered
