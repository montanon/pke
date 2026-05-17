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
from pke_backend.models import LEDGER_VERSION, EventType, LedgerEntry
from pke_backend.protocol.ledger import LedgerEventType


def test_table_name_is_ledger_entries() -> None:
    assert LedgerEntry.__tablename__ == "ledger_entries"


def test_table_registered_on_base_metadata() -> None:
    assert "ledger_entries" in Base.metadata.tables


def test_mapper_registered_against_base_registry() -> None:
    mapped_classes = {mapper.class_ for mapper in Base.registry.mappers}
    assert LedgerEntry in mapped_classes


def test_event_type_is_protocol_enum() -> None:
    assert EventType is LedgerEventType


def test_event_type_has_exactly_five_protocol_values() -> None:
    expected = {
        "SNAPSHOT_COMMITTED",
        "WITNESS_ATTESTED",
        "KEY_GRANTED",
        "REPORTED",
        "FROZEN",
    }
    actual = {member.value for member in EventType}
    assert actual == expected
    assert len(list(EventType)) == 5


def test_ledger_version_constant() -> None:
    assert LEDGER_VERSION == "0.1"


def test_every_column_uses_mapped_annotation() -> None:
    """AC #3: no ``Any`` leakage; ``Mapped[T]`` is used for every column."""
    hints = typing.get_type_hints(LedgerEntry)
    column_attrs = {col.key for col in LedgerEntry.__mapper__.column_attrs}
    assert column_attrs, "expected at least one mapped column"
    for attr in column_attrs:
        hint = hints[attr]
        assert get_origin(hint) is Mapped, f"{attr} is not Mapped[...]: {hint!r}"
        (inner,) = get_args(hint)
        assert inner is not Any, f"{attr} leaks Any in Mapped[Any]"


def test_column_types_match_spec() -> None:
    table = LedgerEntry.__table__
    assert isinstance(table.c.id.type, BigInteger)
    assert isinstance(table.c.ledger_entry_id.type, PG_UUID)
    assert isinstance(table.c.event_type.type, SQLEnum)
    assert isinstance(table.c.snapshot_id.type, PG_UUID)
    assert isinstance(table.c.payload_hash.type, LargeBinary)
    assert isinstance(table.c.previous_entry_hash.type, LargeBinary)
    assert isinstance(table.c.entry_timestamp.type, TIMESTAMP)
    assert isinstance(table.c.entry_hash.type, LargeBinary)
    assert isinstance(table.c.version.type, String)


def test_fixed_length_hash_columns_are_32_bytes() -> None:
    table = LedgerEntry.__table__
    for name in ("payload_hash", "previous_entry_hash", "entry_hash"):
        length = table.c[name].type.length
        assert length == 32, f"{name} length is {length}, expected 32"


def test_version_column_is_varchar_16() -> None:
    assert LedgerEntry.__table__.c.version.type.length == 16


def test_event_type_postgres_enum_name() -> None:
    sql_enum = LedgerEntry.__table__.c.event_type.type
    assert isinstance(sql_enum, SQLEnum)
    assert sql_enum.name == "event_type"
    assert sql_enum.native_enum is True


def test_nullability_matches_spec() -> None:
    table = LedgerEntry.__table__
    assert table.c.id.nullable is False
    assert table.c.ledger_entry_id.nullable is False
    assert table.c.event_type.nullable is False
    assert table.c.snapshot_id.nullable is False
    assert table.c.payload_hash.nullable is False
    assert table.c.previous_entry_hash.nullable is True  # genesis row
    assert table.c.entry_timestamp.nullable is False
    assert table.c.entry_hash.nullable is False
    assert table.c.version.nullable is False


def test_uniqueness_constraints() -> None:
    table = LedgerEntry.__table__
    assert table.c.ledger_entry_id.unique is True
    assert table.c.entry_hash.unique is True


def test_primary_key_is_id() -> None:
    pk_cols = [col.name for col in LedgerEntry.__table__.primary_key.columns]
    assert pk_cols == ["id"]


def test_entry_timestamp_has_server_default_now() -> None:
    server_default = LedgerEntry.__table__.c.entry_timestamp.server_default
    assert server_default is not None


def test_indexes_declared_on_expected_columns() -> None:
    indexes = LedgerEntry.__table__.indexes
    indexed_column_sets = {tuple(col.name for col in idx.columns) for idx in indexes}
    assert ("snapshot_id",) in indexed_column_sets
    assert ("event_type",) in indexed_column_sets
    assert ("entry_timestamp",) in indexed_column_sets


def test_indexes_have_stable_names() -> None:
    names = {idx.name for idx in LedgerEntry.__table__.indexes if isinstance(idx, Index)}
    assert "ix_ledger_entries_snapshot_id" in names
    assert "ix_ledger_entries_event_type" in names
    assert "ix_ledger_entries_entry_timestamp" in names


def test_model_accepts_required_columns_with_correct_types() -> None:
    """AC #1: in-memory instantiation accepts all required columns."""
    snapshot_id = uuid.uuid4()
    ledger_entry_id = uuid.uuid4()
    payload_hash = b"\x11" * 32
    entry_hash = b"\x22" * 32
    previous_entry_hash = b"\x33" * 32
    ts = datetime.now(tz=UTC)

    entry = LedgerEntry(
        ledger_entry_id=ledger_entry_id,
        event_type=EventType.SNAPSHOT_COMMITTED,
        snapshot_id=snapshot_id,
        payload_hash=payload_hash,
        previous_entry_hash=previous_entry_hash,
        entry_timestamp=ts,
        entry_hash=entry_hash,
        version=LEDGER_VERSION,
    )

    assert entry.ledger_entry_id == ledger_entry_id
    assert entry.event_type is EventType.SNAPSHOT_COMMITTED
    assert entry.snapshot_id == snapshot_id
    assert entry.payload_hash == payload_hash
    assert entry.previous_entry_hash == previous_entry_hash
    assert entry.entry_timestamp == ts
    assert entry.entry_hash == entry_hash
    assert entry.version == LEDGER_VERSION


def test_genesis_entry_accepts_null_previous_entry_hash() -> None:
    entry = LedgerEntry(
        ledger_entry_id=uuid.uuid4(),
        event_type=EventType.SNAPSHOT_COMMITTED,
        snapshot_id=uuid.uuid4(),
        payload_hash=b"\x00" * 32,
        previous_entry_hash=None,
        entry_hash=b"\xff" * 32,
    )
    assert entry.previous_entry_hash is None


def test_repr_renders_id_event_type_snapshot_id_and_truncated_hash() -> None:
    snapshot_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    entry_hash = bytes.fromhex("deadbeefcafebabe" + "00" * 24)
    entry = LedgerEntry(
        id=42,
        ledger_entry_id=uuid.uuid4(),
        event_type=EventType.WITNESS_ATTESTED,
        snapshot_id=snapshot_id,
        payload_hash=b"\x00" * 32,
        previous_entry_hash=None,
        entry_hash=entry_hash,
    )
    rendered = repr(entry)
    assert "42" in rendered
    assert "WITNESS_ATTESTED" in rendered
    assert str(snapshot_id) in rendered
    assert "deadbeefcafebabe" in rendered
    # Full hash bytes must NOT leak; only the prefix is rendered.
    assert entry_hash.hex() not in rendered


def test_repr_handles_unset_entry_hash() -> None:
    entry = LedgerEntry(
        id=None,
        ledger_entry_id=uuid.uuid4(),
        event_type=EventType.FROZEN,
        snapshot_id=uuid.uuid4(),
        payload_hash=b"\x00" * 32,
        previous_entry_hash=None,
        entry_hash=b"",
    )
    rendered = repr(entry)
    assert "<unset>" in rendered
    assert "FROZEN" in rendered
