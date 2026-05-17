"""FastAPI surface — routers and shared error infrastructure."""

from __future__ import annotations

from pke_backend.api.errors import HTTPError, error_envelope, register_exception_handlers

__all__ = ["HTTPError", "error_envelope", "register_exception_handlers"]
