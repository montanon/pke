from __future__ import annotations

import pytest

import pke_backend.db as db_module
from pke_backend.db import dispose_engine
from pke_backend.main import app, lifespan


@pytest.mark.asyncio
async def test_lifespan_initializes_and_disposes_engine() -> None:
    await dispose_engine()
    assert db_module._engine is None

    async with lifespan(app):
        assert db_module._engine is not None
        assert db_module._engine.pool._pre_ping is True

    assert db_module._engine is None
    assert db_module._sessionmaker is None
