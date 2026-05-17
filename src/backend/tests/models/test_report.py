"""ORM introspection tests for ``pke_backend.models.report`` (HLAM-77)."""

from __future__ import annotations

import typing
import uuid
from datetime import UTC, datetime
from typing import Any, get_args, get_origin

from sqlalchemy import BigInteger, Index, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped
from sqlalchemy.sql.sqltypes import TIMESTAMP
from sqlalchemy.types import Enum as SQLEnum

from pke_backend.db import Base
from pke_backend.models import REPORT_VERSION, ReasonCategory, Report

EXPECTED_REASON_VALUES = {
    "abuse_concern",
    "legal_request",
    "owner_request",
    "other",
}


def test_table_name_is_reports() -> None:
    assert Report.__tablename__ == "reports"


def test_table_registered_on_base_metadata() -> None:
    assert "reports" in Base.metadata.tables


def test_mapper_registered_against_base_registry() -> None:
    mapped_classes = {mapper.class_ for mapper in Base.registry.mappers}
    assert Report in mapped_classes


def test_reason_category_re_exported_from_models() -> None:
    from pke_backend.protocol.report_action import ReasonCategory as ProtocolEnum

    assert ReasonCategory is ProtocolEnum


def test_report_version_re_exported_from_models() -> None:
    assert REPORT_VERSION == "0.1"


def test_every_column_uses_mapped_annotation() -> None:
    """AC #7: ``Mapped[T]`` is used for every column; no ``Any`` leakage."""
    hints = typing.get_type_hints(Report)
    column_attrs = {col.key for col in Report.__mapper__.column_attrs}
    assert column_attrs, "expected at least one mapped column"
    for attr in column_attrs:
        hint = hints[attr]
        assert get_origin(hint) is Mapped, f"{attr} is not Mapped[...]: {hint!r}"
        (inner,) = get_args(hint)
        assert inner is not Any, f"{attr} leaks Any in Mapped[Any]"


def test_column_types_match_spec() -> None:
    table = Report.__table__
    assert isinstance(table.c.id.type, BigInteger)
    assert isinstance(table.c.report_id.type, PG_UUID)
    assert isinstance(table.c.snapshot_id.type, PG_UUID)
    assert isinstance(table.c.reason_category.type, SQLEnum)
    assert isinstance(table.c.reported_by_signing_public_key.type, LargeBinary)
    assert isinstance(table.c.report_status.type, String)
    assert isinstance(table.c.created_at.type, TIMESTAMP)
    assert isinstance(table.c.report_signature.type, LargeBinary)


def test_reason_category_postgres_enum_name() -> None:
    """AC #2: ENUM type is named ``reason_category`` with 4 labels."""
    sql_enum = Report.__table__.c.reason_category.type
    assert isinstance(sql_enum, SQLEnum)
    assert sql_enum.name == "reason_category"
    assert sql_enum.native_enum is True
    assert set(sql_enum.enums) == EXPECTED_REASON_VALUES
    assert len(sql_enum.enums) == 4


def test_report_status_column_is_varchar_32() -> None:
    assert Report.__table__.c.report_status.type.length == 32


def test_nullability_matches_spec() -> None:
    table = Report.__table__
    assert table.c.id.nullable is False
    assert table.c.report_id.nullable is False
    assert table.c.snapshot_id.nullable is False
    assert table.c.reason_category.nullable is False
    assert table.c.reported_by_signing_public_key.nullable is False
    assert table.c.report_status.nullable is False
    assert table.c.created_at.nullable is False
    assert table.c.report_signature.nullable is False


def test_report_id_uniqueness() -> None:
    assert Report.__table__.c.report_id.unique is True


def test_primary_key_is_id() -> None:
    pk_cols = [col.name for col in Report.__table__.primary_key.columns]
    assert pk_cols == ["id"]


def test_created_at_has_server_default() -> None:
    assert Report.__table__.c.created_at.server_default is not None


def test_report_status_server_default_is_pending() -> None:
    server_default = Report.__table__.c.report_status.server_default
    assert server_default is not None
    # ``DefaultClause.arg`` is a ``TextClause`` for ``sa.text("'pending'")``.
    assert "pending" in str(server_default.arg)


def test_snapshot_id_fk_targets_snapshots_with_restrict() -> None:
    """Edge case 1: ``ON DELETE RESTRICT`` on the snapshots FK."""
    fks = list(Report.__table__.c.snapshot_id.foreign_keys)
    assert len(fks) == 1
    fk = fks[0]
    assert fk.target_fullname == "snapshots.snapshot_id"
    assert fk.ondelete == "RESTRICT"
    assert fk.name == "fk_reports_snapshot_id"


def test_indexes_declared_on_expected_columns() -> None:
    """AC #6: index on ``snapshot_id``."""
    indexes = Report.__table__.indexes
    indexed_column_sets = {tuple(col.name for col in idx.columns) for idx in indexes}
    assert ("snapshot_id",) in indexed_column_sets


def test_indexes_have_stable_names() -> None:
    names = {idx.name for idx in Report.__table__.indexes if isinstance(idx, Index)}
    assert "ix_reports_snapshot_id" in names


def test_model_accepts_required_columns_with_correct_types() -> None:
    """AC #1: in-memory instantiation accepts all required columns."""
    report_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    reported_by = b"\x10" * 32
    signature = b"\x20" * 64
    ts = datetime.now(tz=UTC)

    report = Report(
        report_id=report_id,
        snapshot_id=snapshot_id,
        reason_category=ReasonCategory.ABUSE_CONCERN,
        reported_by_signing_public_key=reported_by,
        report_status="pending",
        created_at=ts,
        report_signature=signature,
    )

    assert report.report_id == report_id
    assert report.snapshot_id == snapshot_id
    assert report.reason_category is ReasonCategory.ABUSE_CONCERN
    assert report.reported_by_signing_public_key == reported_by
    assert report.report_status == "pending"
    assert report.created_at == ts
    assert report.report_signature == signature


def test_repr_renders_id_reason_snapshot_id_and_truncated_report_id() -> None:
    """STRIDE Info Disclosure: ``__repr__`` truncates UUIDs."""
    report_id = uuid.UUID("aabbccdd-1111-2222-3333-444455556666")
    snapshot_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    report = Report(
        id=42,
        report_id=report_id,
        snapshot_id=snapshot_id,
        reason_category=ReasonCategory.LEGAL_REQUEST,
        reported_by_signing_public_key=b"\x00" * 32,
        report_status="pending",
        report_signature=b"\x00" * 64,
    )
    rendered = repr(report)
    assert "42" in rendered
    assert "legal_request" in rendered
    assert str(snapshot_id) in rendered
    assert "aabbccdd" in rendered
    # Full report_id hex must NOT leak; only the prefix is rendered.
    assert report_id.hex not in rendered


def test_repr_handles_unset_report_id() -> None:
    report = Report(
        id=None,
        report_id=None,
        snapshot_id=uuid.uuid4(),
        reason_category=ReasonCategory.OTHER,
        reported_by_signing_public_key=b"\x00" * 32,
        report_status="pending",
        report_signature=b"\x00" * 64,
    )
    rendered = repr(report)
    assert "<unset>" in rendered
    assert "other" in rendered
