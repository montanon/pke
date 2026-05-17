from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

import pke_backend.db as db_module
from pke_backend.db import dispose_engine, get_engine, get_session


@pytest.mark.asyncio
async def test_get_engine_sets_pool_pre_ping() -> None:
    await dispose_engine()
    engine = get_engine()
    try:
        assert engine.pool._pre_ping is True
    finally:
        await dispose_engine()


@pytest.mark.asyncio
async def test_dispose_engine_resets_module_state() -> None:
    await dispose_engine()
    _ = get_engine()
    assert db_module._engine is not None
    await dispose_engine()
    assert db_module._engine is None
    assert db_module._sessionmaker is None


@pytest.mark.asyncio
async def test_get_session_yields_async_session() -> None:
    await dispose_engine()
    engine = get_engine()
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await dispose_engine()
        pytest.skip(f"postgres not reachable: {exc}")

    agen = get_session()
    session = await agen.__anext__()
    try:
        assert isinstance(session, AsyncSession)
        result = await session.execute(text("SELECT 1"))
        assert result.scalar_one() == 1
    finally:
        with pytest.raises(StopAsyncIteration):
            await agen.__anext__()
        await dispose_engine()
