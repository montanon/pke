from __future__ import annotations

import base64
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_decode, b64url_encode
from pke_backend.schemas.key_grant import (
    ECDSA_P1363_SIGNATURE_BYTES,
    RECIPIENT_PUBLIC_KEY_BYTES,
    SIGNING_PUBLIC_KEY_BYTES,
    WRAPPED_SNAPSHOT_KEY_BYTES,
    KeyGrantIn,
    KeyGrantOut,
    PersistedKeyGrant,
)


def _uncompressed_p256_bytes() -> bytes:
    # 0x04 || X(32) || Y(32) — random body is fine; KeyGrantIn only checks length.
    return b"\x04" + secrets.token_bytes(64)


def _valid_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": "key_grant",
        "version": "0.1",
        "grant_id": str(uuid.uuid4()),
        "snapshot_id": str(uuid.uuid4()),
        "recipient_encryption_public_key": b64url_encode(_uncompressed_p256_bytes()),
        "wrapped_snapshot_key": b64url_encode(secrets.token_bytes(WRAPPED_SNAPSHOT_KEY_BYTES)),
        "wrapping_algorithm": "ecdhp256+aesgcm256",
        "granted_by_signing_public_key": b64url_encode(_uncompressed_p256_bytes()),
        "grant_timestamp": "2026-05-15T00:01:00Z",
        "grant_signature": b64url_encode(secrets.token_bytes(ECDSA_P1363_SIGNATURE_BYTES)),
    }
    base.update(overrides)
    return base


# ---------- KeyGrantIn: acceptance criteria ----------


def test_ac1_well_formed_payload_validates() -> None:
    payload = _valid_payload()
    inst = KeyGrantIn.model_validate(payload)
    assert inst.type == "key_grant"
    assert inst.version == "0.1"
    assert isinstance(inst.recipient_encryption_public_key, bytes)
    assert len(inst.recipient_encryption_public_key) == RECIPIENT_PUBLIC_KEY_BYTES
    assert isinstance(inst.wrapped_snapshot_key, bytes)
    assert len(inst.wrapped_snapshot_key) == WRAPPED_SNAPSHOT_KEY_BYTES
    assert isinstance(inst.granted_by_signing_public_key, bytes)
    assert len(inst.granted_by_signing_public_key) == SIGNING_PUBLIC_KEY_BYTES
    assert isinstance(inst.grant_signature, bytes)
    assert len(inst.grant_signature) == ECDSA_P1363_SIGNATURE_BYTES
    assert inst.grant_timestamp.tzinfo is UTC


def test_ac2_canonical_body_bytes_is_idempotent() -> None:
    inst = KeyGrantIn.model_validate(_valid_payload())
    assert inst.canonical_body_bytes() == inst.canonical_body_bytes()


def test_ac3_canonical_body_bytes_matches_canonicalize_of_dump_exclude_signature() -> None:
    inst = KeyGrantIn.model_validate(_valid_payload())
    assert inst.canonical_body_bytes() == canonicalize(inst.dump_exclude_signature())


@pytest.mark.parametrize(
    "algo",
    [
        "rsa-oaep",
        "ecdhp256+aesgcm256-v2",
        "",
        "ECDHP256+AESGCM256",
        " ecdhp256+aesgcm256",
        "ecdhp256+aesgcm256 ",
    ],
)
def test_ac4_rejects_disallowed_wrapping_algorithm(algo: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        KeyGrantIn.model_validate(_valid_payload(wrapping_algorithm=algo))
    # Error message names the allowlist so the failure mode is actionable.
    assert "allowlist" in str(exc_info.value).lower()


@pytest.mark.parametrize("length", [0, 59, 61, 60 - 1, 60 + 1, 120])
def test_ac5_rejects_wrapped_key_wrong_length(length: int) -> None:
    payload = _valid_payload(wrapped_snapshot_key=b64url_encode(b"\x00" * length))
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(payload)


def test_ac5_accepts_exactly_60_bytes() -> None:
    payload = _valid_payload(wrapped_snapshot_key=b64url_encode(b"\x00" * WRAPPED_SNAPSHOT_KEY_BYTES))
    KeyGrantIn.model_validate(payload)


@pytest.mark.parametrize("length", [0, 64, 66, 65 - 1, 65 + 1, 130])
def test_ac6_rejects_recipient_pubkey_wrong_length(length: int) -> None:
    payload = _valid_payload(recipient_encryption_public_key=b64url_encode(b"\x00" * length))
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(payload)


def test_ac6_accepts_exactly_65_bytes() -> None:
    payload = _valid_payload(
        recipient_encryption_public_key=b64url_encode(b"\x04" + b"\x01" * (RECIPIENT_PUBLIC_KEY_BYTES - 1))
    )
    KeyGrantIn.model_validate(payload)


# ---------- KeyGrantIn: edge cases ----------


@pytest.mark.parametrize("raw_len", [58, 59])
def test_edge_case_rejects_padded_base64_input(raw_len: int) -> None:
    # 58 raw bytes -> b64 with trailing "==", 59 raw bytes -> single "=".
    # The strict b64url decoder rejects any "=" before any length check fires,
    # so the size of the underlying payload doesn't matter here.
    padded = base64.urlsafe_b64encode(b"\x00" * raw_len).decode("ascii")
    assert padded.endswith("=")  # sanity-check the fixture
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(_valid_payload(wrapped_snapshot_key=padded))


def test_edge_case_rejects_empty_grant_id() -> None:
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(_valid_payload(grant_id=""))


def test_edge_case_rejects_non_uuid_grant_id() -> None:
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(_valid_payload(grant_id="not-a-uuid"))


@pytest.mark.parametrize("version", ["0.2", "0.1.0", "1.0", "v0.1", "", "0.10"])
def test_rejects_mismatched_version_literal(version: str) -> None:
    # HLAM-3 §Versioning: refuse mismatched versions before any crypto.
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(_valid_payload(version=version))


def test_rejects_unknown_top_level_field() -> None:
    payload = _valid_payload()
    payload["__unexpected__"] = "x"
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(payload)


def test_rejects_missing_grant_signature() -> None:
    payload = _valid_payload()
    del payload["grant_signature"]
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(payload)


def test_signing_pubkey_length_check_rejects_64() -> None:
    payload = _valid_payload(granted_by_signing_public_key=b64url_encode(b"\x00" * 64))
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(payload)


def test_grant_signature_length_check_rejects_63() -> None:
    payload = _valid_payload(grant_signature=b64url_encode(b"\x00" * 63))
    with pytest.raises(ValidationError):
        KeyGrantIn.model_validate(payload)


def test_dump_exclude_signature_omits_only_grant_signature() -> None:
    inst = KeyGrantIn.model_validate(_valid_payload())
    body = inst.dump_exclude_signature()
    assert isinstance(body, dict)
    assert "grant_signature" not in body
    # Every other field is present.
    expected = {
        "type",
        "version",
        "grant_id",
        "snapshot_id",
        "recipient_encryption_public_key",
        "wrapped_snapshot_key",
        "wrapping_algorithm",
        "granted_by_signing_public_key",
        "grant_timestamp",
    }
    assert set(body.keys()) == expected


def test_canonical_body_bytes_is_sorted_minified_utf8() -> None:
    inst = KeyGrantIn.model_validate(_valid_payload())
    body = inst.canonical_body_bytes()
    # Sorted keys: the very first key after `{"` must be alphabetically smallest.
    # Among the 9 non-signature fields the smallest is "grant_id".
    assert body.startswith(b'{"grant_id":')
    # Minified: no spaces around separators.
    assert b", " not in body
    assert b": " not in body
    # No trailing newline.
    assert not body.endswith(b"\n")


# ---------- KeyGrantOut: AC #7 ----------


@dataclass
class _FakeOrm:
    grant_id: uuid.UUID
    snapshot_id: uuid.UUID
    recipient_encryption_public_key: str
    wrapped_snapshot_key: bytes
    wrapping_algorithm: str
    granted_by_signing_public_key: str
    grant_timestamp: datetime
    grant_signature: bytes
    version: str
    created_at: datetime


def _fake_orm() -> _FakeOrm:
    recipient = b64url_encode(_uncompressed_p256_bytes())
    granter = b64url_encode(_uncompressed_p256_bytes())
    return _FakeOrm(
        grant_id=uuid.uuid4(),
        snapshot_id=uuid.uuid4(),
        recipient_encryption_public_key=recipient,
        wrapped_snapshot_key=secrets.token_bytes(WRAPPED_SNAPSHOT_KEY_BYTES),
        wrapping_algorithm="ecdhp256+aesgcm256",
        granted_by_signing_public_key=granter,
        grant_timestamp=datetime(2026, 5, 15, 0, 1, 0, tzinfo=UTC),
        grant_signature=secrets.token_bytes(ECDSA_P1363_SIGNATURE_BYTES),
        version="0.1",
        created_at=datetime(2026, 5, 15, 0, 1, 5, tzinfo=UTC),
    )


def test_fake_orm_satisfies_persisted_key_grant_protocol() -> None:
    # Structural conformance — confirms the test fixture matches the Protocol used
    # by the production call site in HLAM-40 Story #3.
    fake: PersistedKeyGrant = _fake_orm()
    assert fake.version == "0.1"


def test_ac7_from_persisted_roundtrips_bytes_to_base64url() -> None:
    fake = _fake_orm()
    out = KeyGrantOut.from_persisted(fake, ledger_entry_hash=b"\x00" * 32)
    # bytes columns -> base64url-no-pad strings that decode back to the original bytes.
    assert b64url_decode(out.wrapped_snapshot_key) == fake.wrapped_snapshot_key
    assert b64url_decode(out.grant_signature) == fake.grant_signature
    # String columns (already base64url on the ORM row) -> verbatim.
    assert out.recipient_encryption_public_key == fake.recipient_encryption_public_key
    assert out.granted_by_signing_public_key == fake.granted_by_signing_public_key


def test_ac7_from_persisted_emits_hex_ledger_entry_hash() -> None:
    fake = _fake_orm()
    ledger_hash = b"\xde\xad" + b"\x00" * 30
    out = KeyGrantOut.from_persisted(fake, ledger_entry_hash=ledger_hash)
    assert out.ledger_entry_hash == "dead" + "00" * 30
    # Round-trip back via bytes.fromhex to confirm.
    assert bytes.fromhex(out.ledger_entry_hash) == ledger_hash


def test_ac7_from_persisted_serializes_iso8601_z_timestamps() -> None:
    fake = _fake_orm()
    out = KeyGrantOut.from_persisted(fake, ledger_entry_hash=b"\x00" * 32)
    # In-memory the value is a tz-aware datetime; on the wire (model_dump
    # mode="json") it serializes to a `Z`-suffixed ISO-8601 string via UTCDatetime.
    assert out.grant_timestamp == fake.grant_timestamp
    assert out.created_at == fake.created_at
    dumped = out.model_dump(mode="json")
    assert dumped["grant_timestamp"].endswith("Z")
    assert dumped["created_at"].endswith("Z")


def test_ac7_from_persisted_sets_type_literal() -> None:
    fake = _fake_orm()
    out = KeyGrantOut.from_persisted(fake, ledger_entry_hash=b"\x00" * 32)
    assert out.type == "key_grant"


def test_ac7_from_persisted_preserves_uuids() -> None:
    fake = _fake_orm()
    out = KeyGrantOut.from_persisted(fake, ledger_entry_hash=b"\x00" * 32)
    assert out.grant_id == fake.grant_id
    assert out.snapshot_id == fake.snapshot_id
    # On the wire UUIDs serialise as canonical strings.
    dumped = out.model_dump(mode="json")
    assert dumped["grant_id"] == str(fake.grant_id)
    assert dumped["snapshot_id"] == str(fake.snapshot_id)


def test_keygrantout_round_trips_through_model_validate() -> None:
    # The output of model_dump(mode="json") must itself validate as a KeyGrantOut
    # — proves that grant_timestamp's UTCDatetime + uuid string round-trips work.
    fake = _fake_orm()
    out = KeyGrantOut.from_persisted(fake, ledger_entry_hash=b"\x00" * 32)
    reparsed = KeyGrantOut.model_validate(out.model_dump(mode="json"))
    assert reparsed == out


def test_keygrantout_rejects_unknown_field() -> None:
    fake = _fake_orm()
    out = KeyGrantOut.from_persisted(fake, ledger_entry_hash=b"\x00" * 32)
    payload = out.model_dump(mode="json")
    payload["__hax__"] = "x"
    with pytest.raises(ValidationError):
        KeyGrantOut.model_validate(payload)


def test_keygrantout_rejects_mismatched_version() -> None:
    fake = _fake_orm()
    out = KeyGrantOut.from_persisted(fake, ledger_entry_hash=b"\x00" * 32)
    payload = out.model_dump(mode="json")
    payload["version"] = "0.2"
    with pytest.raises(ValidationError):
        KeyGrantOut.model_validate(payload)
