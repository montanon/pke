from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://pke:pke@localhost:5432/pke"  # pragma: allowlist secret
    DEBUG: bool = False
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]
    BLOB_ROOT: Path = Path("./blobs")

    model_config = SettingsConfigDict(
        env_prefix="PKE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
