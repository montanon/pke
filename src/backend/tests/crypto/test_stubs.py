from __future__ import annotations

from collections.abc import Callable

import pytest

StubCall = tuple[str, Callable[..., object], tuple[object, ...]]


def test_stub_helpers_raise_not_implemented(helper_stub_calls: list[StubCall]) -> None:
    for name, fn, args in helper_stub_calls:
        with pytest.raises(NotImplementedError):
            fn(*args)
        assert name


def test_stub_primitives_raise_not_implemented(
    primitive_stub_calls: list[StubCall],
) -> None:
    for name, fn, args in primitive_stub_calls:
        with pytest.raises(NotImplementedError):
            fn(*args)
        assert name
