"""ORM introspection tests for ``pke_backend.models.freeze`` (HLAM-77)."""

from __future__ import annotations

import typing
import uuid
from datetime import UTC, datetime
from typing import Any, get_args, get_origin

from sqlalchemy import BigInteger, Index, LargeBinary, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped
from sqlalchemy.sql.sqltypes import TIMESTAMP

from pke_backend.db import Base
from pke_backend.models import FREEZE_VERSION, Freeze


def test_table_name_is_freezes() -> None:
    assert Freeze.__tablename__ == "freezes"


def test_table_registered_on_base_metadata() -> None:
    assert "freezes" in Base.metadata.tables


def test_mapper_registered_against_base_registry() -> None:
    mapped_classes = {mapper.class_ for mapper in Base.registry.mappers}
    assert Freeze in mapped_classes


def test_freeze_version_re_exported_from_models() -> None:
    assert FREEZE_VERSION == "0.1"


def test_every_column_uses_mapped_annotation() -> None:
    """AC #7: ``Mapped[T]`` is used for every column; no ``Any`` leakage."""
    hints = typing.get_type_hints(Freeze)
    column_attrs = {col.key for col in Freeze.__mapper__.column_attrs}
    assert column_attrs, "expected at least one mapped column"
    for attr in column_attrs:
        hint = hints[attr]
        assert get_origin(hint) is Mapped, f"{attr} is not Mapped[...]: {hint!r}"
        (inner,) = get_args(hint)
        assert inner is not Any, f"{attr} leaks Any in Mapped[Any]"


def test_column_types_match_spec() -> None:
    table = Freeze.__table__
    assert isinstance(table.c.id.type, BigInteger)
    assert isinstance(table.c.freeze_id.type, PG_UUID)
    assert isinstance(table.c.snapshot_id.type, PG_UUID)
    assert isinstance(table.c.triggered_by_report_id.type, PG_UUID)
    assert isinstance(table.c.freeze_status.type, String)
    assert isinstance(table.c.created_at.type, TIMESTAMP)
    assert isinstance(table.c.freeze_signature.type, LargeBinary)


def test_freeze_status_column_is_varchar_32() -> None:
    assert Freeze.__table__.c.freeze_status.type.length == 32


def test_nullability_matches_spec() -> None:
    table = Freeze.__table__
    assert table.c.id.nullable is False
    assert table.c.freeze_id.nullable is False
    assert table.c.snapshot_id.nullable is False
    assert table.c.triggered_by_report_id.nullable is False
    assert table.c.freeze_status.nullable is False
    assert table.c.created_at.nullable is False
    assert table.c.freeze_signature.nullable is False


def test_freeze_id_uniqueness() -> None:
    assert Freeze.__table__.c.freeze_id.unique is True


def test_snapshot_id_unique_constraint_named_uq_freezes_snapshot_id() -> None:
    """AC #3: UNIQUE on ``snapshot_id`` enforces single-freeze-per-snapshot."""
    unique_constraints = [
        constraint for constraint in Freeze.__table__.constraints if isinstance(constraint, UniqueConstraint)
    ]
    named = {constraint.name: constraint for constraint in unique_constraints}
    assert "uq_freezes_snapshot_id" in named
    constraint = named["uq_freezes_snapshot_id"]
    assert [col.name for col in constraint.columns] == ["snapshot_id"]


def test_triggered_by_report_id_fk_targets_reports_with_restrict() -> None:
    """AC #4: FK to ``reports(report_id)`` with ``ON DELETE RESTRICT``."""
    fks = list(Freeze.__table__.c.triggered_by_report_id.foreign_keys)
    assert len(fks) == 1
    fk = fks[0]
    assert fk.target_fullname == "reports.report_id"
    assert fk.ondelete == "RESTRICT"
    assert fk.name == "fk_freezes_triggered_by_report_id"


def test_primary_key_is_id() -> None:
    pk_cols = [col.name for col in Freeze.__table__.primary_key.columns]
    assert pk_cols == ["id"]


def test_created_at_has_server_default() -> None:
    assert Freeze.__table__.c.created_at.server_default is not None


def test_freeze_status_server_default_is_active() -> None:
    server_default = Freeze.__table__.c.freeze_status.server_default
    assert server_default is not None
    assert "active" in str(server_default.arg)


def test_indexes_declared_on_expected_columns() -> None:
    """AC #6: index on ``snapshot_id``."""
    indexes = Freeze.__table__.indexes
    indexed_column_sets = {tuple(col.name for col in idx.columns) for idx in indexes}
    assert ("snapshot_id",) in indexed_column_sets


def test_indexes_have_stable_names() -> None:
    names = {idx.name for idx in Freeze.__table__.indexes if isinstance(idx, Index)}
    assert "ix_freezes_snapshot_id" in names


def test_model_accepts_required_columns_with_correct_types() -> None:
    """AC #1: in-memory instantiation accepts all required columns."""
    freeze_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    triggered_by = uuid.uuid4()
    signature = b"\x77" * 64
    ts = datetime.now(tz=UTC)

    freeze = Freeze(
        freeze_id=freeze_id,
        snapshot_id=snapshot_id,
        triggered_by_report_id=triggered_by,
        freeze_status="active",
        created_at=ts,
        freeze_signature=signature,
    )

    assert freeze.freeze_id == freeze_id
    assert freeze.snapshot_id == snapshot_id
    assert freeze.triggered_by_report_id == triggered_by
    assert freeze.freeze_status == "active"
    assert freeze.created_at == ts
    assert freeze.freeze_signature == signature


def test_repr_truncates_uuids_and_does_not_leak_full_hex() -> None:
    """STRIDE Info Disclosure: ``__repr__`` truncates UUIDs."""
    freeze_id = uuid.UUID("aaaaaaaa-1111-2222-3333-444444444444")
    triggered_by = uuid.UUID("bbbbbbbb-1111-2222-3333-444444444444")
    snapshot_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    freeze = Freeze(
        id=99,
        freeze_id=freeze_id,
        snapshot_id=snapshot_id,
        triggered_by_report_id=triggered_by,
        freeze_status="active",
        freeze_signature=b"\x00" * 64,
    )
    rendered = repr(freeze)
    assert "99" in rendered
    assert str(snapshot_id) in rendered
    assert "aaaaaaaa" in rendered
    assert "bbbbbbbb" in rendered
    # Full UUID hex must NOT leak; only the prefix is rendered.
    assert freeze_id.hex not in rendered
    assert triggered_by.hex not in rendered


def test_repr_handles_unset_ids() -> None:
    freeze = Freeze(
        id=None,
        freeze_id=None,
        snapshot_id=uuid.uuid4(),
        triggered_by_report_id=None,
        freeze_status="active",
        freeze_signature=b"\x00" * 64,
    )
    rendered = repr(freeze)
    assert rendered.count("<unset>") == 2
