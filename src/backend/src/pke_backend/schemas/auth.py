"""Pydantic request/response models for ``/v1/auth/*`` (HLAM-122).

Validation rules per HLAM-122:

* ``username``: 3–32 chars, lowercase ASCII letters / digits / underscore.
  The case-folding step happens at the request layer here so the service
  receives a normalized value to pass to the ORM.
* ``password``: 8–1024 chars. No complexity rules.

Response models intentionally **do not** expose ``password_hash`` — both
``AuthResponse`` and ``UserPublic`` are sealed against accidental leakage
by listing the fields explicitly rather than inheriting from the ORM.
"""

from __future__ import annotations

import re
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_REGEX = re.compile(r"^[a-z0-9_]+$")
USERNAME_MIN = 3
USERNAME_MAX = 32
PASSWORD_MIN = 8
PASSWORD_MAX = 1024


class _Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=USERNAME_MIN, max_length=USERNAME_MAX)
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        folded = value.casefold()
        if not USERNAME_REGEX.match(folded):
            msg = "username must match ^[a-z0-9_]+$ after case-folding"
            raise ValueError(msg)
        return folded


class RegisterRequest(_Credentials):
    """Body for ``POST /v1/auth/register``."""


class LoginRequest(_Credentials):
    """Body for ``POST /v1/auth/login``."""


class UserPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: uuid.UUID
    username: str


class AuthResponse(BaseModel):
    """Body for ``register`` (201) and ``login`` (200)."""

    model_config = ConfigDict(extra="forbid")

    token: str
    user: UserPublic
