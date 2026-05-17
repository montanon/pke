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

from pke_backend.crypto.errors import (
    CanonicalEncodingError,
    EncodingError,
    SignatureFormatError,
    SignatureVerificationError,
)

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
    if not isinstance(exc, HTTPError):  # pragma: no cover — dispatched by FastAPI
        raise TypeError(f"unexpected exception class {type(exc).__name__}")
    return JSONResponse(
        status_code=exc.status_code,
        content=error_envelope(exc.error, exc.detail),
    )


async def _handle_signature_error(_: Request, exc: Exception) -> JSONResponse:
    # Both ``SignatureFormatError`` and ``SignatureVerificationError`` map to
    # 401: from the client's perspective, the request did not prove possession
    # of the claimed signing key. The detail string deliberately omits the
    # underlying ``reason`` to avoid leaking validator internals.
    if not isinstance(exc, (SignatureFormatError, SignatureVerificationError)):  # pragma: no cover
        raise TypeError(f"unexpected exception class {type(exc).__name__}")
    return JSONResponse(
        status_code=401,
        content=error_envelope("signature_invalid", "signature verification failed"),
    )


def _sanitize_validation_errors(exc: RequestValidationError) -> str:
    """Build a safe ``detail`` string from a Pydantic validation error.

    Pydantic's ``errors()`` payload includes the offending ``input`` value
    verbatim per failing field. For binary fields (signatures, pubkeys, etc.)
    that means the request body's raw bytes would round-trip into the
    response. We project to ``loc + type + msg`` and drop ``input``/``ctx``.
    """
    safe = [
        {
            "loc": ".".join(str(part) for part in err.get("loc", ())),
            "type": err.get("type", ""),
            "msg": err.get("msg", ""),
        }
        for err in exc.errors()
    ]
    detail = str(safe)
    if len(detail) > _VALIDATION_DETAIL_MAX_CHARS:
        detail = detail[:_VALIDATION_DETAIL_MAX_CHARS] + "...[truncated]"
    return detail


async def _handle_validation_error(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # pragma: no cover — dispatched by FastAPI
        raise TypeError(f"unexpected exception class {type(exc).__name__}")
    return JSONResponse(
        status_code=422,
        content=error_envelope("invalid_payload", _sanitize_validation_errors(exc)),
    )


async def _handle_encoding_error(_: Request, exc: Exception) -> JSONResponse:
    """Map crypto decode errors (raised inside Pydantic validators) to 422.

    ``EncodingError`` (and its parent ``CanonicalEncodingError``) is not a
    ``ValueError``, so Pydantic v2 does not wrap it into ``ValidationError``.
    Without this handler a malformed base64url field on a request body would
    surface as a 500 — see ``protocol/types.py::_decode_b64url``.

    The detail string deliberately omits ``exc.reason`` to avoid echoing the
    failure mode (length, alphabet) back to the client.
    """
    if not isinstance(exc, (EncodingError, CanonicalEncodingError)):  # pragma: no cover
        raise TypeError(f"unexpected exception class {type(exc).__name__}")
    return JSONResponse(
        status_code=422,
        content=error_envelope("invalid_payload", "binary field decode failed"),
    )


_Handler = Callable[[Request, Exception], Awaitable[JSONResponse]]


def register_exception_handlers(app: FastAPI) -> None:
    """Register HLAM-79's envelope-shaped exception handlers on ``app``."""
    app.add_exception_handler(HTTPError, _handle_http_error)
    app.add_exception_handler(SignatureFormatError, _handle_signature_error)
    app.add_exception_handler(SignatureVerificationError, _handle_signature_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(EncodingError, _handle_encoding_error)
    app.add_exception_handler(CanonicalEncodingError, _handle_encoding_error)
