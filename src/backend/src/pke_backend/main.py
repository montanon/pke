from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pke_backend.api.auth import router as auth_router
from pke_backend.api.errors import register_exception_handlers
from pke_backend.api.freezes import router as freezes_router
from pke_backend.api.reports import router as reports_router
from pke_backend.config import get_settings
from pke_backend.db import dispose_engine, get_engine
from pke_backend.security.errors import (
    DuplicateUsernameError,
    InvalidCredentialsError,
    UnauthenticatedError,
    duplicate_username_handler,
    invalid_credentials_handler,
    unauthenticated_handler,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    get_engine()
    try:
        yield
    finally:
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="PKE Backend", debug=settings.DEBUG, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_exception_handler(UnauthenticatedError, unauthenticated_handler)
    app.add_exception_handler(InvalidCredentialsError, invalid_credentials_handler)
    app.add_exception_handler(DuplicateUsernameError, duplicate_username_handler)

    app.include_router(auth_router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    register_exception_handlers(app)
    app.include_router(reports_router)
    app.include_router(freezes_router)

    return app


app = create_app()
