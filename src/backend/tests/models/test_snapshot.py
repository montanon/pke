from __future__ import annotations

import typing
import uuid
from datetime import UTC, datetime
from typing import Any, get_args, get_origin

from sqlalchemy import Index, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped
from sqlalchemy.sql.sqltypes import TIMESTAMP

from pke_backend.db import Base
from pke_backend.models import (
    CIPHERTEXT_HASH_BYTES,
    SESSION_NONCE_BYTES,
    SNAPSHOT_VERSION,
    Snapshot,
)


def test_table_name_is_snapshots() -> None:
    assert Snapshot.__tablename__ == "snapshots"


def test_table_registered_on_base_metadata() -> None:
    assert "snapshots" in Base.metadata.tables


def test_mapper_registered_against_base_registry() -> None:
    mapped_classes = {mapper.class_ for mapper in Base.registry.mappers}
    assert Snapshot in mapped_classes


def test_snapshot_version_constant() -> None:
    assert SNAPSHOT_VERSION == "0.1"


def test_session_nonce_bytes_constant() -> None:
    assert SESSION_NONCE_BYTES == 16


def test_ciphertext_hash_bytes_constant() -> None:
    assert CIPHERTEXT_HASH_BYTES == 32


def test_every_column_uses_mapped_annotation() -> None:
    """AC #2: every column uses Mapped[T]; no bare Any leak in Mapped[Any].

    Note: dict[str, Any] is allowed because the outer arg of Mapped[...] is
    dict[...] — the Any lives one layer down, where it's required by the
    JSONB schema-less contract.
    """
    hints = typing.get_type_hints(Snapshot)
    column_attrs = {col.key for col in Snapshot.__mapper__.column_attrs}
    assert column_attrs, "expected at least one mapped column"
    for attr in column_attrs:
        hint = hints[attr]
        assert get_origin(hint) is Mapped, f"{attr} is not Mapped[...]: {hint!r}"
        (inner,) = get_args(hint)
        assert inner is not Any, f"{attr} leaks Any in Mapped[Any]"


def test_column_types_match_spec() -> None:
    table = Snapshot.__table__
    assert isinstance(table.c.snapshot_id.type, PG_UUID)
    assert isinstance(table.c.ciphertext_hash.type, LargeBinary)
    assert isinstance(table.c.owner_signing_public_key.type, LargeBinary)
    assert isinstance(table.c.owner_encryption_public_key.type, LargeBinary)
    assert isinstance(table.c.capture_timestamp.type, TIMESTAMP)
    assert isinstance(table.c.metadata_policy.type, JSONB)
    assert isinstance(table.c.session_nonce.type, LargeBinary)
    assert isinstance(table.c.owner_signature.type, LargeBinary)
    assert isinstance(table.c.version.type, String)
    assert isinstance(table.c.blob_storage_uri.type, Text)
    assert isinstance(table.c.created_at.type, TIMESTAMP)


def test_fixed_length_binary_columns() -> None:
    table = Snapshot.__table__
    assert table.c.ciphertext_hash.type.length == CIPHERTEXT_HASH_BYTES
    assert table.c.session_nonce.type.length == SESSION_NONCE_BYTES


def test_unbounded_binary_columns_have_no_length() -> None:
    table = Snapshot.__table__
    assert table.c.owner_signing_public_key.type.length is None
    assert table.c.owner_encryption_public_key.type.length is None
    assert table.c.owner_signature.type.length is None


def test_version_column_is_varchar_16() -> None:
    assert Snapshot.__table__.c.version.type.length == 16


def test_timestamp_columns_are_timezone_aware() -> None:
    table = Snapshot.__table__
    assert table.c.capture_timestamp.type.timezone is True
    assert table.c.created_at.type.timezone is True


def test_nullability_matches_spec() -> None:
    table = Snapshot.__table__
    for col in table.c:
        assert col.nullable is False, f"{col.name} should be NOT NULL"


def test_primary_key_is_snapshot_id() -> None:
    pk_cols = [col.name for col in Snapshot.__table__.primary_key.columns]
    assert pk_cols == ["snapshot_id"]


def test_composite_unique_constraint_declared() -> None:
    table = Snapshot.__table__
    unique_constraints = [c for c in table.constraints if isinstance(c, UniqueConstraint)]
    matching = [c for c in unique_constraints if c.name == "uq_snapshots_owner_pk_session_nonce"]
    assert len(matching) == 1, "expected exactly one named UNIQUE constraint"
    constrained = [col.name for col in matching[0].columns]
    assert constrained == ["owner_signing_public_key", "session_nonce"]


def test_indexes_declared_on_expected_columns() -> None:
    indexes = Snapshot.__table__.indexes
    indexed_column_sets = {tuple(col.name for col in idx.columns) for idx in indexes}
    assert ("owner_signing_public_key",) in indexed_column_sets
    assert ("created_at",) in indexed_column_sets


def test_indexes_have_stable_names() -> None:
    names = {idx.name for idx in Snapshot.__table__.indexes if isinstance(idx, Index)}
    assert "ix_snapshots_owner_signing_public_key" in names
    assert "ix_snapshots_created_at" in names


def test_created_at_has_server_default_now() -> None:
    server_default = Snapshot.__table__.c.created_at.server_default
    assert server_default is not None


def test_version_has_server_default() -> None:
    server_default = Snapshot.__table__.c.version.server_default
    assert server_default is not None


def test_model_accepts_required_columns_with_correct_types() -> None:
    """AC #1: in-memory instantiation accepts all required columns."""
    snapshot_id = uuid.uuid4()
    ciphertext_hash = b"\x11" * 32
    session_nonce = b"\x22" * 16
    owner_signing_public_key = b"\x33" * 33
    owner_encryption_public_key = b"\x44" * 33
    owner_signature = b"\x55" * 64
    ts = datetime.now(tz=UTC)
    metadata_policy = {
        "location_public": False,
        "location_precision": "city",
        "media_type": "photo",
    }

    snapshot = Snapshot(
        snapshot_id=snapshot_id,
        ciphertext_hash=ciphertext_hash,
        owner_signing_public_key=owner_signing_public_key,
        owner_encryption_public_key=owner_encryption_public_key,
        capture_timestamp=ts,
        metadata_policy=metadata_policy,
        session_nonce=session_nonce,
        owner_signature=owner_signature,
        version=SNAPSHOT_VERSION,
        blob_storage_uri="blob://example/snap_test_001",
    )

    assert snapshot.snapshot_id == snapshot_id
    assert snapshot.ciphertext_hash == ciphertext_hash
    assert snapshot.owner_signing_public_key == owner_signing_public_key
    assert snapshot.owner_encryption_public_key == owner_encryption_public_key
    assert snapshot.capture_timestamp == ts
    assert snapshot.metadata_policy == metadata_policy
    assert snapshot.session_nonce == session_nonce
    assert snapshot.owner_signature == owner_signature
    assert snapshot.version == SNAPSHOT_VERSION
    assert snapshot.blob_storage_uri == "blob://example/snap_test_001"


def test_repr_redacts_ciphertext_hash() -> None:
    snapshot_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    ciphertext_hash = bytes.fromhex("deadbeefcafebabe" + "00" * 24)
    snapshot = Snapshot(
        snapshot_id=snapshot_id,
        ciphertext_hash=ciphertext_hash,
        owner_signing_public_key=b"\x00",
        owner_encryption_public_key=b"\x00",
        capture_timestamp=datetime.now(tz=UTC),
        metadata_policy={"location_public": False, "media_type": "photo"},
        session_nonce=b"\x00" * 16,
        owner_signature=b"\x00",
        version=SNAPSHOT_VERSION,
        blob_storage_uri="blob://x",
    )
    rendered = repr(snapshot)
    assert str(snapshot_id) in rendered
    assert "deadbeefcafebabe" in rendered
    assert SNAPSHOT_VERSION in rendered
    # Full hash bytes must NOT leak; only the prefix is rendered.
    assert ciphertext_hash.hex() not in rendered


def test_repr_handles_unset_ciphertext_hash() -> None:
    snapshot = Snapshot(
        snapshot_id=uuid.uuid4(),
        ciphertext_hash=b"",
        owner_signing_public_key=b"\x00",
        owner_encryption_public_key=b"\x00",
        capture_timestamp=datetime.now(tz=UTC),
        metadata_policy={"location_public": False, "media_type": "photo"},
        session_nonce=b"\x00" * 16,
        owner_signature=b"\x00",
        version=SNAPSHOT_VERSION,
        blob_storage_uri="blob://x",
    )
    rendered = repr(snapshot)
    assert "<unset>" in rendered
