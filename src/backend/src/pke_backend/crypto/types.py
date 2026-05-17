"""Typed primitives shared across the crypto package.

`JsonValue` mirrors Swift's `JSONValue` enum (`.string`, `.int`, `.bool`, `.null`, `.array`, `.object`).
"""

from __future__ import annotations

from typing import TypeAlias

__all__ = ["JsonValue"]

JsonValue: TypeAlias = str | int | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
