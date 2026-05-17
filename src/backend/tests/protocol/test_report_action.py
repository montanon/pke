"""Protocol-enum tests for ``pke_backend.protocol.report_action`` (HLAM-77)."""

from __future__ import annotations

from enum import StrEnum

from pke_backend.protocol import report_action
from pke_backend.protocol.report_action import REPORT_VERSION, ReasonCategory

EXPECTED_REASON_VALUES = {
    "abuse_concern",
    "legal_request",
    "owner_request",
    "other",
}


def test_reason_category_has_exactly_four_members() -> None:
    """AC #2 — `reason_category` ENUM has exactly 4 labels."""
    assert len(list(ReasonCategory)) == 4


def test_reason_category_values_match_protocol_spec() -> None:
    """AC #2 — values match `context/05_data_model_public.md`."""
    actual = {member.value for member in ReasonCategory}
    assert actual == EXPECTED_REASON_VALUES


def test_reason_category_member_names() -> None:
    expected_names = {"ABUSE_CONCERN", "LEGAL_REQUEST", "OWNER_REQUEST", "OTHER"}
    assert {member.name for member in ReasonCategory} == expected_names


def test_reason_category_is_str_enum() -> None:
    assert issubclass(ReasonCategory, StrEnum)


def test_report_version_constant() -> None:
    assert REPORT_VERSION == "0.1"


def test_report_action_module_exports_public_symbols() -> None:
    assert "ReasonCategory" in report_action.__all__
    assert "REPORT_VERSION" in report_action.__all__
