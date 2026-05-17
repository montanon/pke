from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

SCHEMAS_DIR = Path(__file__).resolve().parents[3] / "shared" / "schemas"
EXAMPLES_DIR = Path(__file__).resolve().parents[4] / "context" / "examples"

REPORT_SCHEMA_PATH = SCHEMAS_DIR / "report.json"
FREEZE_SCHEMA_PATH = SCHEMAS_DIR / "freeze.json"
REPORT_EXAMPLE_PATH = EXAMPLES_DIR / "report.example.json"
FREEZE_EXAMPLE_PATH = EXAMPLES_DIR / "freeze.example.json"

REPORT_REQUIRED = {
    "type",
    "version",
    "report_id",
    "snapshot_id",
    "reason_category",
    "reported_by_signing_public_key",
    "report_timestamp",
    "report_signature",
}
FREEZE_REQUIRED = {
    "type",
    "version",
    "freeze_id",
    "snapshot_id",
    "triggered_by",
    "frozen_by_signing_public_key",
    "freeze_timestamp",
    "freeze_signature",
}
REASON_CATEGORIES = ["abuse_concern", "legal_request", "owner_request", "other"]
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _validator(schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(schema, format_checker=FormatChecker())


# ---------------------------------------------------------------------------
# AC #1 — schemas are valid JSON and declare draft 2020-12
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [REPORT_SCHEMA_PATH, FREEZE_SCHEMA_PATH], ids=["report", "freeze"])
def test_schema_is_valid_json(path: Path) -> None:
    _load_json(path)


@pytest.mark.parametrize("path", [REPORT_SCHEMA_PATH, FREEZE_SCHEMA_PATH], ids=["report", "freeze"])
def test_schema_declares_draft_2020_12(path: Path) -> None:
    schema = _load_json(path)
    assert schema.get("$schema") == DRAFT_2020_12


@pytest.mark.parametrize("path", [REPORT_SCHEMA_PATH, FREEZE_SCHEMA_PATH], ids=["report", "freeze"])
def test_schema_is_well_formed_meta(path: Path) -> None:
    Draft202012Validator.check_schema(_load_json(path))


# ---------------------------------------------------------------------------
# AC #2, #4 — required field sets
# ---------------------------------------------------------------------------


def test_report_required_fields() -> None:
    schema = _load_json(REPORT_SCHEMA_PATH)
    assert set(schema["required"]) == REPORT_REQUIRED
    assert len(schema["required"]) == 8


def test_freeze_required_fields() -> None:
    schema = _load_json(FREEZE_SCHEMA_PATH)
    assert set(schema["required"]) == FREEZE_REQUIRED
    assert len(schema["required"]) == 8


# ---------------------------------------------------------------------------
# AC #3 — reason_category enum
# ---------------------------------------------------------------------------


def test_report_reason_category_enum_exact() -> None:
    schema = _load_json(REPORT_SCHEMA_PATH)
    enum = schema["properties"]["reason_category"]["enum"]
    assert enum == REASON_CATEGORIES


# ---------------------------------------------------------------------------
# Edge case — additionalProperties: false (top-level)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [REPORT_SCHEMA_PATH, FREEZE_SCHEMA_PATH], ids=["report", "freeze"])
def test_schema_top_level_additional_properties_forbidden(path: Path) -> None:
    schema = _load_json(path)
    assert schema.get("additionalProperties") is False


# ---------------------------------------------------------------------------
# Discriminator — type const
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected_type"),
    [(REPORT_SCHEMA_PATH, "report"), (FREEZE_SCHEMA_PATH, "freeze")],
    ids=["report", "freeze"],
)
def test_schema_type_discriminator_is_const(path: Path, expected_type: str) -> None:
    schema = _load_json(path)
    assert schema["properties"]["type"] == {"const": expected_type}


# ---------------------------------------------------------------------------
# Edge case — timestamps declare date-time format
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "field"),
    [(REPORT_SCHEMA_PATH, "report_timestamp"), (FREEZE_SCHEMA_PATH, "freeze_timestamp")],
    ids=["report", "freeze"],
)
def test_schema_timestamp_is_date_time(path: Path, field: str) -> None:
    schema = _load_json(path)
    spec = schema["properties"][field]
    assert spec.get("type") == "string"
    assert spec.get("format") == "date-time"


# ---------------------------------------------------------------------------
# AC #6 — MANIFEST and README reference the two new schemas
# ---------------------------------------------------------------------------


def test_manifest_lists_report_and_freeze_schemas() -> None:
    repo_root = Path(__file__).resolve().parents[4]
    manifest = _load_json(repo_root / "context" / "MANIFEST.json")
    schema_files = manifest.get("schema_files", [])
    assert "src/shared/schemas/report.json" in schema_files
    assert "src/shared/schemas/freeze.json" in schema_files


def test_readme_mentions_report_and_freeze_schemas() -> None:
    repo_root = Path(__file__).resolve().parents[4]
    readme = (repo_root / "context" / "README.md").read_text()
    assert "report.json" in readme
    assert "freeze.json" in readme


# ---------------------------------------------------------------------------
# AC #5 — example files validate against schemas
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("schema_path", "example_path"),
    [
        (REPORT_SCHEMA_PATH, REPORT_EXAMPLE_PATH),
        (FREEZE_SCHEMA_PATH, FREEZE_EXAMPLE_PATH),
    ],
    ids=["report", "freeze"],
)
def test_example_file_validates_against_schema(schema_path: Path, example_path: Path) -> None:
    schema = _load_json(schema_path)
    example = _load_json(example_path)
    _validator(schema).validate(example)


# ---------------------------------------------------------------------------
# Edge cases — rejection paths
# ---------------------------------------------------------------------------


def test_report_rejects_non_rfc3339_timestamp() -> None:
    schema = _load_json(REPORT_SCHEMA_PATH)
    example = _load_json(REPORT_EXAMPLE_PATH)
    example["report_timestamp"] = "not-a-timestamp"
    with pytest.raises(ValidationError):
        _validator(schema).validate(example)


def test_freeze_rejects_non_rfc3339_timestamp() -> None:
    schema = _load_json(FREEZE_SCHEMA_PATH)
    example = _load_json(FREEZE_EXAMPLE_PATH)
    example["freeze_timestamp"] = "2026/05/15"
    with pytest.raises(ValidationError):
        _validator(schema).validate(example)


def test_report_rejects_unknown_reason_category() -> None:
    schema = _load_json(REPORT_SCHEMA_PATH)
    example = _load_json(REPORT_EXAMPLE_PATH)
    example["reason_category"] = "unknown_reason"
    with pytest.raises(ValidationError):
        _validator(schema).validate(example)


@pytest.mark.parametrize(
    ("schema_path", "example_path"),
    [
        (REPORT_SCHEMA_PATH, REPORT_EXAMPLE_PATH),
        (FREEZE_SCHEMA_PATH, FREEZE_EXAMPLE_PATH),
    ],
    ids=["report", "freeze"],
)
def test_schema_rejects_unknown_top_level_field(schema_path: Path, example_path: Path) -> None:
    schema = _load_json(schema_path)
    example = _load_json(example_path)
    example["extra_field"] = "x"
    with pytest.raises(ValidationError):
        _validator(schema).validate(example)


def test_report_rejects_missing_signature() -> None:
    schema = _load_json(REPORT_SCHEMA_PATH)
    example = _load_json(REPORT_EXAMPLE_PATH)
    del example["report_signature"]
    with pytest.raises(ValidationError):
        _validator(schema).validate(example)


def test_freeze_rejects_missing_triggered_by() -> None:
    schema = _load_json(FREEZE_SCHEMA_PATH)
    example = _load_json(FREEZE_EXAMPLE_PATH)
    del example["triggered_by"]
    with pytest.raises(ValidationError):
        _validator(schema).validate(example)


def test_report_rejects_wrong_type_discriminator() -> None:
    schema = _load_json(REPORT_SCHEMA_PATH)
    example = _load_json(REPORT_EXAMPLE_PATH)
    example["type"] = "freeze"
    with pytest.raises(ValidationError):
        _validator(schema).validate(example)


def test_freeze_rejects_wrong_type_discriminator() -> None:
    schema = _load_json(FREEZE_SCHEMA_PATH)
    example = _load_json(FREEZE_EXAMPLE_PATH)
    example["type"] = "report"
    with pytest.raises(ValidationError):
        _validator(schema).validate(example)
