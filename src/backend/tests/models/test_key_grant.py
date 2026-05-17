"""Unit tests for the ``KeyGrant`` ORM (HLAM-72)."""

from __future__ import annotations

import json
import typing
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, get_args, get_origin

from sqlalchemy import (
    BigInteger,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped
from sqlalchemy.sql.sqltypes import TIMESTAMP

from pke_backend.db import Base
from pke_backend.models import KEY_GRANT_VERSION, KeyGrant

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "shared" / "schemas" / "key_grant.json"

# Fields present in the JSON Schema but intentionally NOT persisted as columns.
# ``type`` is a protocol-envelope discriminator only.
_SCHEMA_ONLY_FIELDS = frozenset({"type"})


def test_table_name_is_key_grants() -> None:
    assert KeyGrant.__tablename__ == "key_grants"


def test_table_registered_on_base_metadata() -> None:
    assert "key_grants" in Base.metadata.tables


def test_mapper_registered_against_base_registry() -> None:
    mapped_classes = {mapper.class_ for mapper in Base.registry.mappers}
    assert KeyGrant in mapped_classes


def test_key_grant_version_constant() -> None:
    assert KEY_GRANT_VERSION == "0.1"


def test_every_column_uses_mapped_annotation() -> None:
    """AC #6: no ``Any`` leakage; ``Mapped[T]`` is used for every column."""
    hints = typing.get_type_hints(KeyGrant)
    column_attrs = {col.key for col in KeyGrant.__mapper__.column_attrs}
    assert column_attrs, "expected at least one mapped column"
    for attr in column_attrs:
        hint = hints[attr]
        assert get_origin(hint) is Mapped, f"{attr} is not Mapped[...]: {hint!r}"
        (inner,) = get_args(hint)
        assert inner is not Any, f"{attr} leaks Any in Mapped[Any]"


def test_column_types_match_spec() -> None:
    table = KeyGrant.__table__
    assert isinstance(table.c.id.type, BigInteger)
    assert isinstance(table.c.grant_id.type, PG_UUID)
    assert isinstance(table.c.snapshot_id.type, PG_UUID)
    assert isinstance(table.c.recipient_encryption_public_key.type, Text)
    assert isinstance(table.c.wrapped_snapshot_key.type, LargeBinary)
    assert isinstance(table.c.wrapping_algorithm.type, String)
    assert isinstance(table.c.granted_by_signing_public_key.type, Text)
    assert isinstance(table.c.grant_timestamp.type, TIMESTAMP)
    assert isinstance(table.c.grant_signature.type, LargeBinary)
    assert isinstance(table.c.version.type, String)
    assert isinstance(table.c.created_at.type, TIMESTAMP)


def test_string_lengths_match_spec() -> None:
    table = KeyGrant.__table__
    assert table.c.wrapping_algorithm.type.length == 64
    assert table.c.version.type.length == 16


def test_timezone_aware_timestamps() -> None:
    table = KeyGrant.__table__
    assert table.c.grant_timestamp.type.timezone is True
    assert table.c.created_at.type.timezone is True


def test_nullability_all_not_null() -> None:
    table = KeyGrant.__table__
    for column in table.columns:
        assert column.nullable is False, f"{column.name} is unexpectedly nullable"


def test_primary_key_is_id_bigint() -> None:
    pk_cols = list(KeyGrant.__table__.primary_key.columns)
    assert [col.name for col in pk_cols] == ["id"]
    assert isinstance(pk_cols[0].type, BigInteger)
    assert pk_cols[0].autoincrement is True


def test_grant_id_unique_constraint_present() -> None:
    assert KeyGrant.__table__.c.grant_id.unique is True


def test_composite_unique_constraint_present() -> None:
    """AC #2: UNIQUE on (snapshot_id, recipient_encryption_public_key)."""
    composite_uniques = [
        constraint
        for constraint in KeyGrant.__table__.constraints
        if isinstance(constraint, UniqueConstraint) and len(constraint.columns) >= 2
    ]
    assert len(composite_uniques) == 1
    constraint = composite_uniques[0]
    assert constraint.name == "uq_key_grants_snapshot_recipient"
    column_names = [col.name for col in constraint.columns]
    assert column_names == ["snapshot_id", "recipient_encryption_public_key"]


def test_recipient_index_present() -> None:
    """AC #5: recipient_encryption_public_key has its own BTREE index."""
    names = {idx.name for idx in KeyGrant.__table__.indexes if isinstance(idx, Index)}
    assert "ix_key_grants_recipient_encryption_public_key" in names


def test_snapshot_id_index_present() -> None:
    names = {idx.name for idx in KeyGrant.__table__.indexes if isinstance(idx, Index)}
    assert "ix_key_grants_snapshot_id" in names


def test_indexes_target_expected_columns() -> None:
    indexed_column_sets = {
        tuple(col.name for col in idx.columns) for idx in KeyGrant.__table__.indexes if isinstance(idx, Index)
    }
    assert ("snapshot_id",) in indexed_column_sets
    assert ("recipient_encryption_public_key",) in indexed_column_sets


def test_created_at_has_server_default_now() -> None:
    server_default = KeyGrant.__table__.c.created_at.server_default
    assert server_default is not None
    # `func.now()` is rendered as the textual ``now()`` in the migration; the
    # ORM-side server_default is the SQLAlchemy ``FunctionElement``. Either way
    # the column carries a non-None server-side default.


def test_version_has_default_and_server_default() -> None:
    column = KeyGrant.__table__.c.version
    assert column.default is not None
    assert column.default.arg == KEY_GRANT_VERSION
    assert column.server_default is not None
    assert column.server_default.arg == KEY_GRANT_VERSION


def test_snapshot_id_has_fk_to_snapshots_with_restrict() -> None:
    """AC #3: FK to ``snapshots(snapshot_id)`` with ``ON DELETE RESTRICT``."""
    fks = list(KeyGrant.__table__.c.snapshot_id.foreign_keys)
    assert len(fks) == 1
    fk = fks[0]
    assert fk.column.table.name == "snapshots"
    assert fk.column.name == "snapshot_id"
    assert fk.ondelete == "RESTRICT"
    assert fk.name == "fk_key_grants_snapshot_id"


def test_model_accepts_required_columns_with_correct_types() -> None:
    """AC #1: in-memory instantiation accepts all required columns."""
    grant_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    wrapped = b"\x01" * 60
    sig = b"\x02" * 64
    ts = datetime.now(tz=UTC)

    grant = KeyGrant(
        grant_id=grant_id,
        snapshot_id=snapshot_id,
        recipient_encryption_public_key="recipient_test_pub_001",
        wrapped_snapshot_key=wrapped,
        wrapping_algorithm="ecdhp256+aesgcm256",
        granted_by_signing_public_key="owner_test_sig_pub_001",
        grant_timestamp=ts,
        grant_signature=sig,
        version=KEY_GRANT_VERSION,
    )

    assert grant.grant_id == grant_id
    assert grant.snapshot_id == snapshot_id
    assert grant.recipient_encryption_public_key == "recipient_test_pub_001"
    assert grant.wrapped_snapshot_key == wrapped
    assert grant.wrapping_algorithm == "ecdhp256+aesgcm256"
    assert grant.granted_by_signing_public_key == "owner_test_sig_pub_001"
    assert grant.grant_timestamp == ts
    assert grant.grant_signature == sig
    assert grant.version == KEY_GRANT_VERSION


def test_repr_includes_identifiers_and_truncates_secrets() -> None:
    grant_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    snapshot_id = uuid.UUID("66666666-7777-8888-9999-aaaaaaaaaaaa")
    wrapped = bytes.fromhex("deadbeefcafebabe" + "00" * 52)
    grant = KeyGrant(
        id=7,
        grant_id=grant_id,
        snapshot_id=snapshot_id,
        recipient_encryption_public_key="recipient_test_pub_001",
        wrapped_snapshot_key=wrapped,
        wrapping_algorithm="ecdhp256+aesgcm256",
        granted_by_signing_public_key="owner_test_sig_pub_001",
        grant_timestamp=datetime.now(tz=UTC),
        grant_signature=b"\xab" * 64,
    )
    rendered = repr(grant)

    assert "7" in rendered
    assert str(grant_id) in rendered
    assert str(snapshot_id) in rendered
    # Truncated wrapped-key prefix is rendered (first 8 hex chars).
    assert "deadbeef" in rendered
    # Full wrapped-key hex must NOT leak.
    assert wrapped.hex() not in rendered
    # Full grant_signature must NOT leak.
    assert grant.grant_signature.hex() not in rendered  # type: ignore[union-attr]
    # Recipient should be elided to a prefix as well.
    assert "recipient_te" in rendered
    assert "recipient_test_pub_001" not in rendered


def test_repr_handles_unset_wrapped_key() -> None:
    grant = KeyGrant(
        grant_id=uuid.uuid4(),
        snapshot_id=uuid.uuid4(),
        recipient_encryption_public_key="",
        wrapped_snapshot_key=b"",
        wrapping_algorithm="ecdhp256+aesgcm256",
        granted_by_signing_public_key="owner_test_sig_pub_001",
        grant_timestamp=datetime.now(tz=UTC),
        grant_signature=b"\xab" * 64,
    )
    rendered = repr(grant)
    assert "<unset>" in rendered


def test_schema_field_parity_with_key_grant_json() -> None:
    """Every required field in ``key_grant.json`` has a corresponding column.

    Protocol-only fields like ``type`` are excluded.
    """
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    required = set(schema["required"]) - _SCHEMA_ONLY_FIELDS
    column_names = {col.name for col in KeyGrant.__table__.columns}
    missing = required - column_names
    assert missing == set(), f"schema fields not mapped to columns: {missing}"
