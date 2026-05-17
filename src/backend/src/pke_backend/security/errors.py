"""Uniform error-envelope handler for authentication failures.

Returns the ``{"error": {"code, "message"}}`` shape called out by HLAM-122.
HLAM-47 S11 will broaden the same envelope to the rest of the API; for now
only the 401 path is wired here so the bearer-auth surface is testable in
isolation.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse


class UnauthenticatedError(Exception):
    """Raised by :func:`require_user` for any auth-rejection path.

    The message is **deliberately generic** — callers must not include the
    submitted token, username, or any other distinguishing detail in the
    error string. The 401 response shape is identical for missing header,
    wrong scheme, empty token, unknown token, and revoked token.
    """

    def __init__(self, message: str = "Authentication required.") -> None:
        super().__init__(message)
        self.message = message


class InvalidCredentialsError(Exception):
    """Raised by ``POST /v1/auth/login`` on unknown user OR wrong password.

    Same exception, same response body, comparable wall-time → no
    username enumeration via the response.
    """

    def __init__(self, message: str = "Invalid credentials.") -> None:
        super().__init__(message)
        self.message = message


class DuplicateUsernameError(Exception):
    """Raised by ``POST /v1/auth/register`` when the username is taken."""

    def __init__(self, message: str = "Username already taken.") -> None:
        super().__init__(message)
        self.message = message


async def unauthenticated_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    message = exc.message if isinstance(exc, UnauthenticatedError) else "Authentication required."
    return JSONResponse(
        status_code=401,
        content={"error": {"code": "unauthenticated", "message": message}},
    )


async def invalid_credentials_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    message = exc.message if isinstance(exc, InvalidCredentialsError) else "Invalid credentials."
    return JSONResponse(
        status_code=401,
        content={"error": {"code": "invalid_credentials", "message": message}},
    )


async def duplicate_username_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    message = exc.message if isinstance(exc, DuplicateUsernameError) else "Username already taken."
    return JSONResponse(
        status_code=409,
        content={"error": {"code": "duplicate_username", "message": message}},
    )
