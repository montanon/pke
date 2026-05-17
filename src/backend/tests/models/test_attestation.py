from __future__ import annotations

import typing
import uuid
from datetime import UTC, datetime
from typing import Any, get_args, get_origin

from sqlalchemy import BigInteger, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped
from sqlalchemy.sql.sqltypes import TIMESTAMP
from sqlalchemy.types import Enum as SQLEnum

from pke_backend.db import Base
from pke_backend.models import WITNESS_ATTESTATION_VERSION, WitnessAttestation


def test_table_name_is_witness_attestations() -> None:
    assert WitnessAttestation.__tablename__ == "witness_attestations"


def test_table_registered_on_base_metadata() -> None:
    assert "witness_attestations" in Base.metadata.tables


def test_mapper_registered_against_base_registry() -> None:
    mapped_classes = {mapper.class_ for mapper in Base.registry.mappers}
    assert WitnessAttestation in mapped_classes


def test_witness_attestation_version_constant() -> None:
    assert WITNESS_ATTESTATION_VERSION == "0.1"


def test_every_column_uses_mapped_annotation() -> None:
    """AC #5: no ``Any`` leakage; ``Mapped[T]`` is used for every column."""
    hints = typing.get_type_hints(WitnessAttestation)
    column_attrs = {col.key for col in WitnessAttestation.__mapper__.column_attrs}
    assert column_attrs, "expected at least one mapped column"
    for attr in column_attrs:
        hint = hints[attr]
        assert get_origin(hint) is Mapped, f"{attr} is not Mapped[...]: {hint!r}"
        (inner,) = get_args(hint)
        assert inner is not Any, f"{attr} leaks Any in Mapped[Any]"


def test_column_types_match_spec() -> None:
    table = WitnessAttestation.__table__
    assert isinstance(table.c.id.type, BigInteger)
    assert isinstance(table.c.snapshot_id.type, PG_UUID)
    assert isinstance(table.c.witness_signing_public_key.type, Text)
    assert isinstance(table.c.witness_timestamp.type, TIMESTAMP)
    assert isinstance(table.c.transport.type, String)
    assert isinstance(table.c.proximity_claim.type, JSONB)
    assert isinstance(table.c.witness_signature.type, LargeBinary)
    assert isinstance(table.c.version.type, String)
    assert isinstance(table.c.created_at.type, TIMESTAMP)


def test_transport_is_varchar_64() -> None:
    """AC #6: transport is VARCHAR(64), not a PG ENUM."""
    assert WitnessAttestation.__table__.c.transport.type.length == 64


def test_version_column_is_varchar_16() -> None:
    assert WitnessAttestation.__table__.c.version.type.length == 16


def test_witness_signature_has_no_length_constraint() -> None:
    """Edge case #1: DB stores any BYTEA; length is enforced upstream."""
    assert WitnessAttestation.__table__.c.witness_signature.type.length is None


def test_nullability_matches_spec() -> None:
    table = WitnessAttestation.__table__
    assert table.c.id.nullable is False
    assert table.c.snapshot_id.nullable is False
    assert table.c.witness_signing_public_key.nullable is False
    assert table.c.witness_timestamp.nullable is False
    assert table.c.transport.nullable is False
    assert table.c.proximity_claim.nullable is False
    assert table.c.witness_signature.nullable is False
    assert table.c.version.nullable is False
    assert table.c.created_at.nullable is False


def test_primary_key_is_id() -> None:
    pk_cols = [col.name for col in WitnessAttestation.__table__.primary_key.columns]
    assert pk_cols == ["id"]


def test_composite_unique_constraint_present() -> None:
    """AC #2: UNIQUE(snapshot_id, witness_signing_public_key)."""
    table = WitnessAttestation.__table__
    unique_by_name = {
        c.name: tuple(col.name for col in c.columns)
        for c in table.constraints
        if c.__class__.__name__ == "UniqueConstraint"
    }
    assert "uq_witness_attestations_snapshot_witness" in unique_by_name
    cols = unique_by_name["uq_witness_attestations_snapshot_witness"]
    assert cols == ("snapshot_id", "witness_signing_public_key")


def test_snapshot_id_foreign_key_target_and_restrict() -> None:
    """AC #3: FK to snapshots(snapshot_id) ON DELETE RESTRICT.

    Resolved via ``target_fullname`` rather than ``fk.column`` so the test
    remains green before HLAM-61 lands the ``snapshots`` table.
    """
    fks = list(WitnessAttestation.__table__.c.snapshot_id.foreign_keys)
    assert len(fks) == 1
    fk = fks[0]
    assert fk.target_fullname == "snapshots.snapshot_id"
    assert fk.ondelete == "RESTRICT"
    assert fk.name == "fk_witness_attestations_snapshot_id"


def test_created_at_has_server_default_now() -> None:
    server_default = WitnessAttestation.__table__.c.created_at.server_default
    assert server_default is not None


def test_version_has_default_and_server_default() -> None:
    col = WitnessAttestation.__table__.c.version
    assert col.default is not None
    assert col.default.arg == WITNESS_ATTESTATION_VERSION
    assert col.server_default is not None


def test_transport_is_string_not_enum() -> None:
    """AC #6: transport is free-form VARCHAR, not a PG ENUM."""
    transport_type = WitnessAttestation.__table__.c.transport.type
    assert isinstance(transport_type, String)
    assert not isinstance(transport_type, SQLEnum)


def test_model_accepts_required_columns_with_correct_types() -> None:
    """AC #1: in-memory instantiation accepts all required columns."""
    snapshot_id = uuid.uuid4()
    witness_key = "witness_test_signing_public_key_001"
    witness_timestamp = datetime.now(tz=UTC)
    transport = "multipeerconnectivity"
    proximity = {"method": "nearby_session", "exact_location_public": False}
    signature = b"\x11" * 64

    attestation = WitnessAttestation(
        snapshot_id=snapshot_id,
        witness_signing_public_key=witness_key,
        witness_timestamp=witness_timestamp,
        transport=transport,
        proximity_claim=proximity,
        witness_signature=signature,
        version=WITNESS_ATTESTATION_VERSION,
    )

    assert attestation.snapshot_id == snapshot_id
    assert attestation.witness_signing_public_key == witness_key
    assert attestation.witness_timestamp == witness_timestamp
    assert attestation.transport == transport
    assert attestation.proximity_claim == proximity
    assert attestation.witness_signature == signature
    assert attestation.version == WITNESS_ATTESTATION_VERSION


def test_repr_truncates_signature_and_omits_full_bytes() -> None:
    snapshot_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    signature = bytes.fromhex("deadbeefcafebabe" + "00" * 56)
    attestation = WitnessAttestation(
        id=7,
        snapshot_id=snapshot_id,
        witness_signing_public_key="k",
        witness_timestamp=datetime.now(tz=UTC),
        transport="multipeerconnectivity",
        proximity_claim={"method": "nearby_session", "exact_location_public": False},
        witness_signature=signature,
    )
    rendered = repr(attestation)
    assert "7" in rendered
    assert str(snapshot_id) in rendered
    assert "deadbeefcafebabe" in rendered
    # Full signature must NOT leak; only the 8-byte hex prefix is rendered.
    assert signature.hex() not in rendered


def test_repr_handles_unset_signature() -> None:
    attestation = WitnessAttestation(
        id=None,
        snapshot_id=uuid.uuid4(),
        witness_signing_public_key="k",
        witness_timestamp=datetime.now(tz=UTC),
        transport="multipeerconnectivity",
        proximity_claim={"method": "nearby_session", "exact_location_public": False},
        witness_signature=b"",
    )
    rendered = repr(attestation)
    assert "<unset>" in rendered


def test_table_args_carries_unique_constraint_only() -> None:
    table_args = WitnessAttestation.__table_args__
    assert isinstance(table_args, tuple)
    assert len(table_args) == 1
    constraint = table_args[0]
    assert constraint.__class__.__name__ == "UniqueConstraint"
    assert constraint.name == "uq_witness_attestations_snapshot_witness"
