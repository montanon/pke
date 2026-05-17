from __future__ import annotations

from collections.abc import Iterator

import pytest

from pke_backend.config import get_settings


@pytest.fixture(autouse=True)
def _reset_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
