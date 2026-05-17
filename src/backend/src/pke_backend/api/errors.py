"""HTTP error envelope + global exception handlers for the FastAPI surface.

Every endpoint error returns the same JSON shape::

    {"error": "<code>", "detail": "<safe message>"}

``code`` is a stable machine identifier the client matches on (e.g.
``snapshot_not_found``, ``signature_invalid``); ``detail`` is a short
human-readable string with no raw input bytes (per the STRIDE info-disclosure
constraint shared across HLAM-79 / HLAM-77).

Services raise either :class:`HTTPError` (when they have a specific code +
status to surface) or one of the crypto errors from
:mod:`pke_backend.crypto.errors`; the registered handlers translate both
into the same envelope.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from pke_backend.crypto.errors import SignatureFormatError, SignatureVerificationError

__all__ = ["HTTPError", "error_envelope", "register_exception_handlers"]

_VALIDATION_DETAIL_MAX_CHARS: Final[int] = 512


class HTTPError(Exception):
    """A status-coded error a service raises to drive the HTTP response.

    Construct with a specific HTTP ``status_code`` (e.g. 404, 409, 422), a
    stable machine ``error`` code (e.g. ``snapshot_not_found``), and a short
    human-readable ``detail``. The detail must never include raw key bytes or
    signature bytes.
    """

    __slots__ = ("detail", "error", "status_code")

    def __init__(self, status_code: int, error: str, detail: str) -> None:
        super().__init__(f"{status_code} {error}: {detail}")
        self.status_code = status_code
        self.error = error
        self.detail = detail


def error_envelope(error: str, detail: str) -> dict[str, str]:
    return {"error": error, "detail": detail}


async def _handle_http_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, HTTPError)
    return JSONResponse(
        status_code=exc.status_code,
        content=error_envelope(exc.error, exc.detail),
    )


async def _handle_signature_error(_: Request, exc: Exception) -> JSONResponse:
    # Both ``SignatureFormatError`` and ``SignatureVerificationError`` map to
    # 401: from the client's perspective, the request did not prove possession
    # of the claimed signing key. The detail string deliberately omits the
    # underlying ``reason`` to avoid leaking validator internals.
    assert isinstance(exc, (SignatureFormatError, SignatureVerificationError))
    return JSONResponse(
        status_code=401,
        content=error_envelope("signature_invalid", "signature verification failed"),
    )


async def _handle_validation_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    # ``RequestValidationError.errors()`` may include the offending input value
    # in ``ctx``; truncate to keep the response size bounded and avoid echoing
    # large or sensitive blobs.
    detail = str(exc.errors())
    if len(detail) > _VALIDATION_DETAIL_MAX_CHARS:
        detail = detail[:_VALIDATION_DETAIL_MAX_CHARS] + "...[truncated]"
    return JSONResponse(
        status_code=422,
        content=error_envelope("invalid_payload", detail),
    )


_Handler = Callable[[Request, Exception], Awaitable[JSONResponse]]


def register_exception_handlers(app: FastAPI) -> None:
    """Register HLAM-79's envelope-shaped exception handlers on ``app``."""
    app.add_exception_handler(HTTPError, _handle_http_error)
    app.add_exception_handler(SignatureFormatError, _handle_signature_error)
    app.add_exception_handler(SignatureVerificationError, _handle_signature_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
