from __future__ import annotations

import pytest

from pke_backend.crypto import JsonValue


def test_jsonvalue_importable_from_package() -> None:
    assert JsonValue is not None


@pytest.mark.parametrize(
    "value",
    [
        "string",
        42,
        True,
        None,
        [1, "two", None, [3]],
        {"k": "v", "nested": {"x": [1, False]}},
    ],
)
def test_jsonvalue_accepts_primitive_examples(value: JsonValue) -> None:
    _: JsonValue = value
    assert _ == value
