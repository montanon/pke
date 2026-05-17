from __future__ import annotations

import pytest

from pke_backend.config import Settings, get_settings


def test_defaults_match_env_sample(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("PKE_DATABASE_URL", "PKE_DEBUG", "PKE_ALLOWED_ORIGINS"):
        monkeypatch.delenv(var, raising=False)
    s = Settings()
    assert s.DATABASE_URL == "postgresql+asyncpg://pke:pke@localhost:5432/pke"  # pragma: allowlist secret
    assert s.DEBUG is False
    assert s.ALLOWED_ORIGINS == ["http://localhost:3000"]


def test_debug_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKE_DEBUG", "true")
    get_settings.cache_clear()
    assert get_settings().DEBUG is True


def test_database_url_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    override = "postgresql+asyncpg://x:y@host:5432/z"  # pragma: allowlist secret
    monkeypatch.setenv("PKE_DATABASE_URL", override)
    get_settings.cache_clear()
    actual = get_settings().DATABASE_URL
    assert actual == override


def test_allowed_origins_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKE_ALLOWED_ORIGINS", '["https://a.example","https://b.example"]')
    get_settings.cache_clear()
    assert get_settings().ALLOWED_ORIGINS == ["https://a.example", "https://b.example"]


def test_lru_cache_returns_same_instance() -> None:
    a = get_settings()
    b = get_settings()
    assert a is b


def test_extra_env_var_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKE_NOT_A_FIELD", "x")
    get_settings.cache_clear()
    s = get_settings()
    assert s.DEBUG is False


def test_cache_clear_picks_up_new_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKE_DEBUG", "false")
    get_settings.cache_clear()
    assert get_settings().DEBUG is False
    monkeypatch.setenv("PKE_DEBUG", "true")
    get_settings.cache_clear()
    assert get_settings().DEBUG is True
