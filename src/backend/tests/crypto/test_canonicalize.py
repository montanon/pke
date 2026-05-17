from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from pke_backend.crypto.canonicalize import MAX_DEPTH, canonicalize
from pke_backend.crypto.errors import CanonicalEncodingError
from pke_backend.crypto.types import JsonValue

VECTORS_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "canonical_json"


def test_empty_dict_returns_braces() -> None:
    assert canonicalize({}) == b"{}"


def test_empty_list_returns_brackets() -> None:
    assert canonicalize([]) == b"[]"


def test_returns_bytes_not_str() -> None:
    result = canonicalize({"a": 1})
    assert isinstance(result, bytes)


def test_no_trailing_newline() -> None:
    result = canonicalize({"a": 1, "b": [1, 2, 3]})
    assert not result.endswith(b"\n")
    assert result.endswith(b"}")


def test_separators_have_no_spaces() -> None:
    result = canonicalize({"a": 1, "b": 2})
    assert result == b'{"a":1,"b":2}'
    assert b", " not in result
    assert b": " not in result


def test_top_level_keys_sorted() -> None:
    result = canonicalize({"b": 1, "a": 2, "c": 3})
    assert result == b'{"a":2,"b":1,"c":3}'


def test_nested_keys_sorted_at_every_level() -> None:
    payload: JsonValue = {
        "z": {"b": 1, "a": 2},
        "a": {"y": {"d": 4, "c": 3}, "x": 1},
    }
    result = canonicalize(payload)
    assert result == b'{"a":{"x":1,"y":{"c":3,"d":4}},"z":{"a":2,"b":1}}'


def test_key_sort_by_utf8_byte_sequence_upper_before_lower() -> None:
    result = canonicalize({"a": 1, "Z": 2})
    assert result == b'{"Z":2,"a":1}'


def test_key_sort_by_utf8_byte_sequence_ascii_before_unicode() -> None:
    result = canonicalize({"é": 1, "a": 2})
    decoded = result.decode("utf-8")
    assert decoded.index('"a"') < decoded.index('"é"')


def test_unicode_value_round_trip_as_utf8_bytes() -> None:
    payload: JsonValue = {"café": "naïve"}
    result = canonicalize(payload)
    assert result == '{"café":"naïve"}'.encode()
    assert json.loads(result.decode("utf-8")) == {"café": "naïve"}


def test_unicode_not_escaped_as_uxxxx() -> None:
    result = canonicalize({"k": "café"})
    assert b"\\u" not in result
    assert "café".encode() in result


def test_nan_rejected() -> None:
    with pytest.raises(CanonicalEncodingError):
        canonicalize({"x": math.nan})  # type: ignore[dict-item]


def test_positive_infinity_rejected() -> None:
    with pytest.raises(CanonicalEncodingError):
        canonicalize({"x": math.inf})  # type: ignore[dict-item]


def test_negative_infinity_rejected() -> None:
    with pytest.raises(CanonicalEncodingError):
        canonicalize({"x": -math.inf})  # type: ignore[dict-item]


def test_nan_at_top_level_rejected() -> None:
    with pytest.raises(CanonicalEncodingError):
        canonicalize(math.nan)  # type: ignore[arg-type]


def test_unsupported_type_rejected() -> None:
    with pytest.raises(CanonicalEncodingError):
        canonicalize({"x": object()})  # type: ignore[dict-item]


def test_canonical_encoding_error_reason_has_no_payload_data() -> None:
    marker = "payload_marker_xyzzy_abcdef"
    try:
        canonicalize({marker: object()})  # type: ignore[dict-item]
    except CanonicalEncodingError as exc:
        assert exc.reason is not None
        assert marker not in exc.reason
    else:
        pytest.fail("expected CanonicalEncodingError")


def test_bool_emitted_as_lowercase() -> None:
    assert canonicalize({"a": True, "b": False}) == b'{"a":true,"b":false}'


def test_none_emitted_as_null() -> None:
    assert canonicalize({"a": None}) == b'{"a":null}'


def test_list_preserves_order_with_mixed_types() -> None:
    payload: JsonValue = [1, "two", True, None, 3.5, [1, 2], {"k": "v"}]
    result = canonicalize(payload)
    assert result == b'[1,"two",true,null,3.5,[1,2],{"k":"v"}]'


def test_array_of_objects_sorts_each_object() -> None:
    payload: JsonValue = [{"b": 1, "a": 2}, {"d": 3, "c": 4}]
    result = canonicalize(payload)
    assert result == b'[{"a":2,"b":1},{"c":4,"d":3}]'


def test_int_emitted_without_decimal() -> None:
    assert canonicalize({"n": 42}) == b'{"n":42}'


def test_negative_int() -> None:
    assert canonicalize({"n": -7}) == b'{"n":-7}'


def test_string_with_special_chars_escaped() -> None:
    result = canonicalize({"k": 'a"b\\c'})
    assert result == b'{"k":"a\\"b\\\\c"}'


def test_depth_at_limit_succeeds() -> None:
    payload: JsonValue = "leaf"
    for _ in range(MAX_DEPTH - 1):
        payload = {"x": payload}
    result = canonicalize(payload)
    assert result.startswith(b'{"x":')
    assert result.endswith(b'"leaf"' + b"}" * (MAX_DEPTH - 1))


def test_depth_over_limit_rejected() -> None:
    payload: JsonValue = "leaf"
    for _ in range(MAX_DEPTH + 5):
        payload = {"x": payload}
    with pytest.raises(CanonicalEncodingError):
        canonicalize(payload)


def test_deeply_nested_list_over_limit_rejected() -> None:
    payload: JsonValue = []
    for _ in range(MAX_DEPTH + 5):
        payload = [payload]
    with pytest.raises(CanonicalEncodingError):
        canonicalize(payload)


def test_scalar_top_level_string() -> None:
    assert canonicalize("hello") == b'"hello"'


def test_scalar_top_level_int() -> None:
    assert canonicalize(123) == b"123"


def test_scalar_top_level_bool() -> None:
    assert canonicalize(True) == b"true"


def test_scalar_top_level_none() -> None:
    assert canonicalize(None) == b"null"


def test_deterministic_output_independent_of_insertion_order() -> None:
    a = canonicalize({"a": 1, "b": 2, "c": 3})
    b = canonicalize({"c": 3, "a": 1, "b": 2})
    c = canonicalize({"b": 2, "c": 3, "a": 1})
    assert a == b == c


def _load_vector(name: str) -> dict[str, object]:
    return json.loads((VECTORS_DIR / name).read_text())


def _vectors(prefix: str) -> list[str]:
    return sorted(p.name for p in VECTORS_DIR.glob(f"{prefix}*.json"))


POSITIVE_VECTORS = _vectors("p")
NEGATIVE_VECTORS = _vectors("n")


def test_canonical_json_vector_directory_populated() -> None:
    assert POSITIVE_VECTORS, "expected at least one positive canonical_json vector"
    assert NEGATIVE_VECTORS, "expected the negative canonical_json vector"


@pytest.mark.parametrize("vector", POSITIVE_VECTORS)
def test_positive_vector_canonical_bytes_match(vector: str) -> None:
    bundle = _load_vector(vector)
    assert bundle["valid"] is True
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    assert canonicalize(inputs["value"]).hex() == expected["canonical_bytes_hex"]


def test_negative_vector_duplicate_key_rejected() -> None:
    bundle = _load_vector("n1-duplicate-key.json")
    assert bundle["valid"] is False
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    assert isinstance(inputs, dict)
    assert isinstance(expected, dict)
    raw = bytes.fromhex(str(inputs["raw_utf8_hex"]))
    # Documented failure mode: duplicate keys must be rejected at decode time.
    with pytest.raises(ValueError):
        json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    assert expected["error"] == "duplicate_key"


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate key at decode time: {key!r}")
        seen.add(key)
    return dict(pairs)
