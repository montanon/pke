from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from pke_backend.protocol import (
    KeyGrant,
    LedgerEntry,
    SnapshotCommitment,
    VerificationReport,
    WitnessAttestation,
)

SCHEMAS_DIR = Path(__file__).resolve().parents[3] / "shared" / "schemas"

MODELS: dict[str, type[BaseModel]] = {
    "snapshot_commitment": SnapshotCommitment,
    "witness_attestation": WitnessAttestation,
    "ledger_entry": LedgerEntry,
    "key_grant": KeyGrant,
    "verification_report": VerificationReport,
}


def _resolve_refs(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if set(node.keys()) == {"$ref"}:
            ref = node["$ref"]
            assert ref.startswith("#/$defs/"), f"unexpected $ref form: {ref}"
            name = ref[len("#/$defs/") :]
            return _resolve_refs(defs[name], defs)
        if "$ref" in node:
            target = _resolve_refs({"$ref": node["$ref"]}, defs)
            merged = {k: v for k, v in node.items() if k != "$ref"}
            if isinstance(target, dict):
                merged = {**target, **merged}
            return _resolve_refs(merged, defs)
        return {k: _resolve_refs(v, defs) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve_refs(v, defs) for v in node]
    return node


def _unwrap_nullable(node: Any) -> Any:
    if isinstance(node, dict):
        if (
            set(node.keys()) <= {"anyOf", "default", "title"}
            and "anyOf" in node
            and isinstance(node["anyOf"], list)
            and len(node["anyOf"]) == 2
            and node.get("default", "__missing__") in (None, "__missing__")
        ):
            null_branches = [b for b in node["anyOf"] if b == {"type": "null"}]
            other_branches = [b for b in node["anyOf"] if b != {"type": "null"}]
            if len(null_branches) == 1 and len(other_branches) == 1:
                return _unwrap_nullable(other_branches[0])
        return {k: _unwrap_nullable(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_unwrap_nullable(v) for v in node]
    return node


def _strip_titles(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _strip_titles(v) for k, v in node.items() if k != "title"}
    if isinstance(node, list):
        return [_strip_titles(v) for v in node]
    return node


def _strip_nested_additional_properties(node: Any) -> Any:
    """Strip `additionalProperties` from nested object subschemas only.

    Walks `properties.*` recursively and removes `additionalProperties`. The
    top-level `additionalProperties` is preserved because this function is
    invoked per-subtree.
    """
    if not isinstance(node, dict):
        return node
    props = node.get("properties")
    if isinstance(props, dict):
        new_props: dict[str, Any] = {}
        for k, v in props.items():
            if isinstance(v, dict):
                v = {kk: vv for kk, vv in v.items() if kk != "additionalProperties"}
                v = _strip_nested_additional_properties(v)
                # Recurse into array items too.
                items = v.get("items")
                if isinstance(items, dict):
                    items = {kk: vv for kk, vv in items.items() if kk != "additionalProperties"}
                    v["items"] = _strip_nested_additional_properties(items)
            new_props[k] = v
        node = {**node, "properties": new_props}
    return node


def _drop_const_type(node: Any) -> Any:
    if isinstance(node, dict):
        if "const" in node and node.get("type") == "string":
            node = {k: v for k, v in node.items() if k != "type"}
        return {k: _drop_const_type(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_drop_const_type(v) for v in node]
    return node


def _drop_default_null(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _drop_default_null(v) for k, v in node.items() if not (k == "default" and v is None)}
    if isinstance(node, list):
        return [_drop_default_null(v) for v in node]
    return node


def _drop_binary_format(node: Any) -> Any:
    """Drop `format: "binary"` Pydantic emits for `Base64UrlBytes` fields.

    Committed schemas declare base64url-encoded fields as plain
    `{"type": "string"}` since the encoding rule is documented in the protocol
    spec, not via the JSON Schema `format` keyword.
    """
    if isinstance(node, dict):
        if node.get("type") == "string" and node.get("format") == "binary":
            node = {k: v for k, v in node.items() if k != "format"}
        return {k: _drop_binary_format(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_drop_binary_format(v) for v in node]
    return node


def _drop_top_level_keys(node: dict[str, Any], keys: set[str]) -> dict[str, Any]:
    return {k: v for k, v in node.items() if k not in keys}


def _normalize_pydantic(schema: dict[str, Any]) -> dict[str, Any]:
    defs = schema.get("$defs", {})
    resolved = _resolve_refs(schema, defs)
    resolved = _drop_top_level_keys(resolved, {"$defs"})
    resolved = _unwrap_nullable(resolved)
    resolved = _strip_titles(resolved)
    resolved = _drop_const_type(resolved)
    resolved = _drop_default_null(resolved)
    resolved = _drop_binary_format(resolved)
    resolved = _strip_nested_additional_properties(resolved)
    return resolved


def _normalize_committed(schema: dict[str, Any]) -> dict[str, Any]:
    out = _drop_top_level_keys(schema, {"$schema", "title"})
    out = _strip_titles(out)
    out = _strip_nested_additional_properties(out)
    return out


def _dumps(node: Any) -> str:
    return json.dumps(node, sort_keys=True, indent=2)


@pytest.mark.parametrize(("name", "model"), list(MODELS.items()))
def test_schema_matches_committed(name: str, model: type[BaseModel]) -> None:
    committed_path = SCHEMAS_DIR / f"{name}.json"
    committed = json.loads(committed_path.read_text())
    emitted = model.model_json_schema()

    expected = _dumps(_normalize_committed(committed))
    actual = _dumps(_normalize_pydantic(emitted))
    assert actual == expected, (
        f"schema drift for {name}:\n--- committed (normalized) ---\n{expected}\n--- pydantic (normalized) ---\n{actual}"
    )


@pytest.mark.parametrize(("name", "model"), list(MODELS.items()))
def test_additional_properties_forbidden(name: str, model: type[BaseModel]) -> None:
    committed = json.loads((SCHEMAS_DIR / f"{name}.json").read_text())
    assert committed.get("additionalProperties") is False, f"{name}.json missing top-level additionalProperties: false"
    assert model.model_config.get("extra") == "forbid", f"{model.__name__} must use ConfigDict(extra='forbid')"
    with pytest.raises(ValidationError):
        model.model_validate({"__unexpected_field__": "x"})
