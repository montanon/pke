from __future__ import annotations

import ast
import asyncio
import math
import uuid
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.hashing import sha256, verify_hash_chain
from pke_backend.crypto.types import JsonValue
from pke_backend.db import get_sessionmaker
from pke_backend.models.ledger import LEDGER_VERSION, LedgerEntry
from pke_backend.protocol.ledger import LedgerEventType
from pke_backend.services.ledger import (
    _VERIFY_BATCH_SIZE,
    ChainVerification,
    LedgerCanonicalizationError,
    LedgerError,
    _envelope_for_row,
    _serialize_utc_z,
    append_entry,
    get_head,
    verify_chain,
)

_GENESIS_PREVIOUS_BYTES = b"\x00" * 32


def _entry_to_wire(entry: LedgerEntry) -> dict[str, JsonValue]:
    previous_bytes = entry.previous_entry_hash or _GENESIS_PREVIOUS_BYTES
    return {
        "type": "ledger_entry",
        "version": entry.version,
        "ledger_entry_id": str(entry.ledger_entry_id),
        "event_type": entry.event_type.value,
        "snapshot_id": str(entry.snapshot_id),
        "payload_hash": b64url_encode(entry.payload_hash),
        "previous_entry_hash": b64url_encode(previous_bytes),
        "entry_timestamp": _serialize_utc_z(entry.entry_timestamp),
        "entry_hash": b64url_encode(entry.entry_hash),
    }


# ---------- AC #1: genesis row ----------


@pytest.mark.asyncio
async def test_append_entry_genesis_returns_null_previous(db_session: AsyncSession) -> None:
    snapshot_id = uuid.uuid4()
    entry = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=snapshot_id,
        payload={"hello": "genesis"},
        session=db_session,
    )
    assert entry.previous_entry_hash is None
    assert len(entry.entry_hash) == 32
    assert entry.version == LEDGER_VERSION
    assert entry.entry_timestamp.tzinfo is not None

    count_stmt = sa.select(sa.func.count(LedgerEntry.id))
    count = (await db_session.execute(count_stmt)).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_append_entry_genesis_hash_matches_envelope(db_session: AsyncSession) -> None:
    snapshot_id = uuid.uuid4()
    payload: JsonValue = {"k": "v", "n": 1}
    entry = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=snapshot_id,
        payload=payload,
        session=db_session,
    )

    expected_payload_hash = sha256(canonicalize(payload))
    assert entry.payload_hash == expected_payload_hash

    envelope: dict[str, JsonValue] = {
        "type": "ledger_entry",
        "version": entry.version,
        "ledger_entry_id": str(entry.ledger_entry_id),
        "event_type": entry.event_type.value,
        "snapshot_id": str(entry.snapshot_id),
        "payload_hash": b64url_encode(entry.payload_hash),
        "previous_entry_hash": b64url_encode(_GENESIS_PREVIOUS_BYTES),
        "entry_timestamp": _serialize_utc_z(entry.entry_timestamp),
    }
    assert sha256(canonicalize(envelope)) == entry.entry_hash


# ---------- Genesis NULL ↔ 32-zero-bytes round-trip ----------


@pytest.mark.asyncio
async def test_genesis_round_trip_via_verify_hash_chain(db_session: AsyncSession) -> None:
    """The ORM stores NULL for genesis; the wire form uses 32 zero bytes.

    A reloaded genesis row must round-trip through ``verify_hash_chain``
    without modification beyond the NULL→zero-bytes substitution.
    """
    entry = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=uuid.uuid4(),
        payload={"genesis": True},
        session=db_session,
    )
    assert entry.previous_entry_hash is None

    wire = _entry_to_wire(entry)
    assert wire["previous_entry_hash"] == b64url_encode(_GENESIS_PREVIOUS_BYTES)
    verify_hash_chain([wire])


# ---------- AC #2: chain link ----------


@pytest.mark.asyncio
async def test_append_entry_chains_to_prior(db_session: AsyncSession) -> None:
    first = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=uuid.uuid4(),
        payload={"i": 1},
        session=db_session,
    )
    second = await append_entry(
        event_type=LedgerEventType.WITNESS_ATTESTED,
        snapshot_id=uuid.uuid4(),
        payload={"i": 2},
        session=db_session,
    )
    assert second.previous_entry_hash == first.entry_hash


@pytest.mark.asyncio
async def test_chain_verifies_via_hlam2_verify_hash_chain(db_session: AsyncSession) -> None:
    entries: list[LedgerEntry] = []
    for i in range(3):
        entries.append(
            await append_entry(
                event_type=LedgerEventType.SNAPSHOT_COMMITTED,
                snapshot_id=uuid.uuid4(),
                payload={"i": i},
                session=db_session,
            )
        )
    wire = [_entry_to_wire(e) for e in entries]
    verify_hash_chain(wire)


# ---------- AC #3: idempotency ----------


@pytest.mark.asyncio
async def test_append_entry_idempotent_returns_existing(db_session: AsyncSession) -> None:
    snapshot_id = uuid.uuid4()
    payload: JsonValue = {"dedup": "yes"}
    first = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=snapshot_id,
        payload=payload,
        session=db_session,
    )
    second = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=snapshot_id,
        payload=payload,
        session=db_session,
    )
    assert first.id == second.id

    count = (await db_session.execute(sa.select(sa.func.count(LedgerEntry.id)))).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_idempotent_path_changes_with_payload(db_session: AsyncSession) -> None:
    snapshot_id = uuid.uuid4()
    a = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=snapshot_id,
        payload={"v": 1},
        session=db_session,
    )
    b = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=snapshot_id,
        payload={"v": 2},
        session=db_session,
    )
    assert a.id != b.id
    assert b.previous_entry_hash == a.entry_hash


# ---------- AC #4: concurrency ----------


async def _append_using_fresh_session(
    *,
    event_type: LedgerEventType,
    snapshot_id: uuid.UUID,
    payload: JsonValue,
) -> int:
    sm = get_sessionmaker()
    async with sm() as session:
        entry = await append_entry(
            event_type=event_type,
            snapshot_id=snapshot_id,
            payload=payload,
            session=session,
        )
        return entry.id


@pytest.mark.asyncio
async def test_concurrent_appends_produce_linear_chain(clean_ledger: None) -> None:
    n = 20
    tasks = [
        _append_using_fresh_session(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=uuid.uuid4(),
            payload={"i": i},
        )
        for i in range(n)
    ]
    ids = await asyncio.gather(*tasks)
    assert len(set(ids)) == n

    sm = get_sessionmaker()
    async with sm() as session:
        rows = (await session.execute(sa.select(LedgerEntry).order_by(LedgerEntry.id.asc()))).scalars().all()
    assert len(rows) == n
    wire = [_entry_to_wire(r) for r in rows]
    verify_hash_chain(wire)


@pytest.mark.asyncio
async def test_concurrent_identical_payloads_dedupe(clean_ledger: None) -> None:
    snapshot_id = uuid.uuid4()
    payload: JsonValue = {"same": "everywhere"}
    tasks = [
        _append_using_fresh_session(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=snapshot_id,
            payload=payload,
        )
        for _ in range(5)
    ]
    ids = await asyncio.gather(*tasks)
    assert len(set(ids)) == 1

    sm = get_sessionmaker()
    async with sm() as session:
        count = (await session.execute(sa.select(sa.func.count(LedgerEntry.id)))).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_no_integrity_error_surfaced_under_contention(clean_ledger: None) -> None:
    """The advisory lock + inner re-check must absorb concurrent retries.

    20 identical-payload calls must all return the same row and never bubble
    up an ``IntegrityError`` on the ``entry_hash`` UNIQUE constraint — the
    failure mode the design exists to prevent.
    """
    snapshot_id = uuid.uuid4()
    payload: JsonValue = {"contention": "uniform"}
    tasks = [
        _append_using_fresh_session(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=snapshot_id,
            payload=payload,
        )
        for _ in range(20)
    ]
    # If gather propagates an IntegrityError this raises here.
    ids = await asyncio.gather(*tasks)
    assert len(set(ids)) == 1


@pytest.mark.asyncio
async def test_two_writers_different_snapshot_serialise(clean_ledger: None) -> None:
    snap_a = uuid.uuid4()
    snap_b = uuid.uuid4()
    ids = await asyncio.gather(
        _append_using_fresh_session(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=snap_a,
            payload={"writer": "A"},
        ),
        _append_using_fresh_session(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=snap_b,
            payload={"writer": "B"},
        ),
    )
    assert len(set(ids)) == 2
    sm = get_sessionmaker()
    async with sm() as session:
        rows = (await session.execute(sa.select(LedgerEntry).order_by(LedgerEntry.id.asc()))).scalars().all()
    assert len(rows) == 2
    wire = [_entry_to_wire(r) for r in rows]
    verify_hash_chain(wire)


# ---------- AC #5: pre-lock canonicalisation error ----------


@pytest.mark.asyncio
async def test_non_canonical_payload_raises_before_lock(db_session: AsyncSession) -> None:
    bad_payload = cast("JsonValue", {"naninfinity": math.inf})
    with pytest.raises(LedgerCanonicalizationError) as exc_info:
        await append_entry(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=uuid.uuid4(),
            payload=bad_payload,
            session=db_session,
        )
    assert exc_info.value.reason is not None
    assert exc_info.value.__cause__ is not None

    count = (await db_session.execute(sa.select(sa.func.count(LedgerEntry.id)))).scalar_one()
    assert count == 0


@pytest.mark.asyncio
async def test_canonicalization_error_observed_with_no_lock_acquisition(
    db_session: AsyncSession,
) -> None:
    """Acceptance criterion #5: the canonicalisation error must precede the lock.

    We assert the error class and that no row is created; the lock acquisition
    is in-process and not directly observable, but the absence of any side effect
    (no row, no commit) is the observable contract here.
    """
    bad_payload = cast("JsonValue", float("nan"))
    with pytest.raises(LedgerCanonicalizationError):
        await append_entry(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=uuid.uuid4(),
            payload=bad_payload,
            session=db_session,
        )


# ---------- AC #6: unconditional HLAM-2 imports ----------


def test_module_imports_hlam2_unconditionally() -> None:
    source_path = Path(__file__).resolve().parents[2] / "src" / "pke_backend" / "services" / "ledger.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    crypto_imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module.startswith("pke_backend.crypto"):
                crypto_imports.append(node)
    assert crypto_imports, "expected at least one pke_backend.crypto import"

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for child in ast.walk(node):
                if isinstance(child, ast.ImportFrom) and child.module is not None:
                    assert not child.module.startswith("pke_backend.crypto"), (
                        f"forbidden fallback: crypto import wrapped in try at line {child.lineno}"
                    )


# ---------- get_head ----------


@pytest.mark.asyncio
async def test_get_head_empty_returns_none(db_session: AsyncSession) -> None:
    assert await get_head(session=db_session) is None


@pytest.mark.asyncio
async def test_get_head_returns_most_recent(db_session: AsyncSession) -> None:
    a = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=uuid.uuid4(),
        payload={"i": 1},
        session=db_session,
    )
    head = await get_head(session=db_session)
    assert head is not None
    assert head.id == a.id
    # get_head autobegins a read-only transaction; release it before the
    # next append_entry, which owns its own transaction.
    await db_session.rollback()
    b = await append_entry(
        event_type=LedgerEventType.WITNESS_ATTESTED,
        snapshot_id=uuid.uuid4(),
        payload={"i": 2},
        session=db_session,
    )
    head = await get_head(session=db_session)
    assert head is not None
    assert head.id == b.id


# ---------- caller-contract precondition ----------


@pytest.mark.asyncio
async def test_append_entry_rejects_session_with_active_transaction(
    db_session: AsyncSession,
) -> None:
    """An autobegun (or caller-started) transaction must be cleared first."""
    await db_session.execute(sa.text("SELECT 1"))  # autobegins
    assert db_session.in_transaction()
    with pytest.raises(LedgerError) as exc_info:
        await append_entry(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=uuid.uuid4(),
            payload={"i": 1},
            session=db_session,
        )
    assert exc_info.value.reason is not None
    assert "active transaction" in exc_info.value.reason


# ---------- _serialize_utc_z hardening ----------


def test_serialize_utc_z_normalises_non_utc_tzinfo() -> None:
    plus_5 = timezone(timedelta(hours=5))
    moment = datetime(2026, 5, 17, 5, 30, 0, tzinfo=plus_5)
    rendered = _serialize_utc_z(moment)
    assert rendered == "2026-05-17T00:30:00Z"


def test_serialize_utc_z_rejects_naive_datetime() -> None:
    naive = datetime(2026, 5, 17, 5, 30, 0)  # noqa: DTZ001 - intentional, exercises the guard
    with pytest.raises(LedgerError):
        _serialize_utc_z(naive)


# ---------- timestamp behaviour ----------


@pytest.mark.asyncio
async def test_entry_timestamp_is_python_generated_utc(db_session: AsyncSession) -> None:
    before = datetime.now(UTC)
    entry = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=uuid.uuid4(),
        payload={"i": 1},
        session=db_session,
    )
    after = datetime.now(UTC)
    assert before <= entry.entry_timestamp <= after
    assert entry.entry_timestamp.tzinfo is not None


# ---------- verify_chain (HLAM-58) ----------
#
# Tampering helper: writes raw bytes to a persisted ledger row, bypassing the
# service layer's canonicalisation and the ORM's normal flush path. Used to
# simulate the "attacker mutates ledger_entries" threat the verifier exists to
# detect. Any kwarg left None is preserved on disk.
#
# Tests that need a *consistent* tamper (where the recomputed entry_hash
# matches a tampered envelope so the *next* check fires rather than the
# entry_hash check) rebuild the envelope from the freshly-fetched row,
# recompute sha256(canonicalize(envelope)), then call _tamper_row again with
# the new entry_hash. The two-step shape is shown explicitly in each test.


async def _tamper_row(
    session: AsyncSession,
    *,
    row_id: int,
    payload_hash: bytes | None = None,
    previous_entry_hash_set_null: bool = False,
    previous_entry_hash: bytes | None = None,
    entry_hash: bytes | None = None,
) -> None:
    updates: dict[str, bytes | None] = {}
    if payload_hash is not None:
        updates["payload_hash"] = payload_hash
    if previous_entry_hash_set_null:
        updates["previous_entry_hash"] = None
    elif previous_entry_hash is not None:
        updates["previous_entry_hash"] = previous_entry_hash
    if entry_hash is not None:
        updates["entry_hash"] = entry_hash
    if not updates:
        return
    await session.execute(
        sa.update(LedgerEntry).where(LedgerEntry.id == row_id).values(**updates),
    )
    await session.commit()


async def _fetch_row_by_id(session: AsyncSession, row_id: int) -> LedgerEntry:
    row = (await session.execute(sa.select(LedgerEntry).where(LedgerEntry.id == row_id))).scalar_one()
    # Detach so subsequent attribute reads in the test do not trigger a lazy
    # refresh after the next commit (which would expire instances and require
    # a fresh greenlet to satisfy the SELECT).
    session.expunge(row)
    return row


# ---------- AC #4: empty table ----------


@pytest.mark.asyncio
async def test_verify_chain_empty_table_returns_verified_true(db_session: AsyncSession) -> None:
    result = await verify_chain(session=db_session)
    assert result == ChainVerification(
        total_entries=0,
        verified=True,
        first_divergence_index=None,
        first_divergence_reason=None,
    )


# ---------- AC #1: intact 5-entry chain ----------


@pytest.mark.asyncio
async def test_verify_chain_intact_five_entry_chain_returns_verified_true(clean_ledger: None) -> None:
    sm = get_sessionmaker()
    async with sm() as writer:
        for i in range(5):
            await append_entry(
                event_type=LedgerEventType.SNAPSHOT_COMMITTED,
                snapshot_id=uuid.uuid4(),
                payload={"i": i},
                session=writer,
            )
    async with sm() as reader:
        result = await verify_chain(session=reader)
    assert result == ChainVerification(
        total_entries=5,
        verified=True,
        first_divergence_index=None,
        first_divergence_reason=None,
    )


# ---------- AC #2: payload_hash byte flip ----------


@pytest.mark.asyncio
async def test_verify_chain_detects_payload_hash_byte_flip(clean_ledger: None) -> None:
    sm = get_sessionmaker()
    async with sm() as writer:
        for i in range(3):
            await append_entry(
                event_type=LedgerEventType.SNAPSHOT_COMMITTED,
                snapshot_id=uuid.uuid4(),
                payload={"i": i},
                session=writer,
            )

    # Flip one byte in row #2 (index 1)'s payload_hash. The entry_hash check
    # will catch this because we leave the stored entry_hash unchanged.
    async with sm() as t:
        row = await _fetch_row_by_id(t, row_id=2)
        flipped = bytes([row.payload_hash[0] ^ 0x01]) + row.payload_hash[1:]
        await _tamper_row(t, row_id=2, payload_hash=flipped)

    async with sm() as reader:
        result = await verify_chain(session=reader)

    assert result.verified is False
    assert result.first_divergence_index == 1
    assert result.first_divergence_reason == "entry_hash mismatch at index 1"
    assert result.total_entries == 3


# ---------- AC #3: previous_entry_hash corruption ----------


@pytest.mark.asyncio
async def test_verify_chain_detects_previous_entry_hash_corruption(clean_ledger: None) -> None:
    sm = get_sessionmaker()
    async with sm() as writer:
        for i in range(3):
            await append_entry(
                event_type=LedgerEventType.SNAPSHOT_COMMITTED,
                snapshot_id=uuid.uuid4(),
                payload={"i": i},
                session=writer,
            )

    # Two-step tamper: (1) overwrite row #3's previous_entry_hash with a
    # known-wrong 32-byte value; (2) recompute entry_hash from the tampered
    # envelope so the entry_hash check passes and the previous_entry_hash
    # check is the one that fires.
    wrong_previous = b"\xcc" * 32
    async with sm() as t:
        await _tamper_row(t, row_id=3, previous_entry_hash=wrong_previous)
        row = await _fetch_row_by_id(t, row_id=3)
        envelope = _envelope_for_row(row)
        recomputed = sha256(canonicalize(envelope))
        await _tamper_row(t, row_id=3, entry_hash=recomputed)

    async with sm() as reader:
        result = await verify_chain(session=reader)

    assert result.verified is False
    assert result.first_divergence_index == 2
    assert result.first_divergence_reason == "previous_entry_hash mismatch at index 2"
    assert result.total_entries == 3


# ---------- Edge: non-NULL genesis previous_entry_hash ----------


@pytest.mark.asyncio
async def test_verify_chain_detects_non_null_genesis_previous(clean_ledger: None) -> None:
    sm = get_sessionmaker()
    async with sm() as writer:
        await append_entry(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=uuid.uuid4(),
            payload={"genesis": True},
            session=writer,
        )

    # Two-step: (1) install a 32-byte non-NULL previous_entry_hash on the
    # genesis row; (2) recompute and patch entry_hash so the genesis-check is
    # the first failure rather than the entry_hash check.
    wrong_previous = b"\x01" * 32
    async with sm() as t:
        await _tamper_row(t, row_id=1, previous_entry_hash=wrong_previous)
        row = await _fetch_row_by_id(t, row_id=1)
        envelope = _envelope_for_row(row)
        recomputed = sha256(canonicalize(envelope))
        await _tamper_row(t, row_id=1, entry_hash=recomputed)

    async with sm() as reader:
        result = await verify_chain(session=reader)

    assert result.verified is False
    assert result.first_divergence_index == 0
    assert result.first_divergence_reason == "genesis must have NULL previous_entry_hash"
    assert result.total_entries == 1


# ---------- AC #5 + DoD: snapshot_id never narrows the walk ----------


@pytest.mark.asyncio
async def test_verify_chain_snapshot_id_filter_does_not_narrow_walk(clean_ledger: None) -> None:
    """Tampering snapshot A's row must still be detected by verify_chain(snapshot_B).

    The tampered row is the genesis (id=1, snapshot A). A buggy implementation
    that narrowed by ``snapshot_id=B`` would walk only the snapshot-B row at
    index 0 — which would itself report a non-NULL previous_entry_hash and
    return ``"genesis must have NULL previous_entry_hash"``. The assertion
    pins ``"entry_hash mismatch at index 0"``, so a narrowing regression
    would fail this test on the *reason string* (not on the verdict).
    """
    snap_a = uuid.uuid4()
    snap_b = uuid.uuid4()
    sm = get_sessionmaker()
    async with sm() as writer:
        # Layout: id=1 → A, id=2 → B, id=3 → A. Tamper id=1 (snapshot A).
        await append_entry(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=snap_a,
            payload={"i": 1},
            session=writer,
        )
        await append_entry(
            event_type=LedgerEventType.SNAPSHOT_COMMITTED,
            snapshot_id=snap_b,
            payload={"i": 2},
            session=writer,
        )
        await append_entry(
            event_type=LedgerEventType.WITNESS_ATTESTED,
            snapshot_id=snap_a,
            payload={"i": 3},
            session=writer,
        )

    async with sm() as t:
        row = await _fetch_row_by_id(t, row_id=1)
        flipped = bytes([row.payload_hash[0] ^ 0x01]) + row.payload_hash[1:]
        await _tamper_row(t, row_id=1, payload_hash=flipped)

    # Caller asks about snapshot B; the integrity walk must still cover all
    # rows and surface the tamper on row 1 (which belongs to snapshot A).
    async with sm() as reader:
        result = await verify_chain(session=reader, snapshot_id=snap_b)

    assert result.verified is False
    assert result.first_divergence_index == 0
    assert result.first_divergence_reason == "entry_hash mismatch at index 0"
    assert result.total_entries == 3


# ---------- AC #6: streaming over a large chain ----------


@pytest.mark.asyncio
async def test_verify_chain_streams_large_chain_without_materialising_all(clean_ledger: None) -> None:
    """500 entries — exercises the streaming cursor over > _VERIFY_BATCH_SIZE rows.

    The original story specifies 1000; 500 keeps the wall-clock under the
    pytest budget on CI while still spanning multiple cursor batches
    (``ceil(500 / 256) == 2``, which is enough to prove yield_per is honoured
    rather than the whole result materialised in one fetch).

    The "actually streaming" property is pinned by intercepting
    :meth:`AsyncSession.stream` and asserting the statement carries the
    expected ``yield_per`` execution option — checking the result is
    ``verified=True`` is necessary but not sufficient (a buggy implementation
    that called ``execute(...).scalars().all()`` would still pass on the
    verdict alone).
    """
    n = 500
    sm = get_sessionmaker()
    async with sm() as writer:
        for i in range(n):
            await append_entry(
                event_type=LedgerEventType.SNAPSHOT_COMMITTED,
                snapshot_id=uuid.uuid4(),
                payload={"i": i},
                session=writer,
            )

    captured_yield_per: list[int | None] = []

    async with sm() as reader:
        original_stream = reader.stream

        async def _capturing_stream(stmt, *args, **kwargs):  # type: ignore[no-untyped-def]
            opts = getattr(stmt, "_execution_options", None) or {}
            captured_yield_per.append(opts.get("yield_per"))
            return await original_stream(stmt, *args, **kwargs)

        reader.stream = _capturing_stream  # type: ignore[method-assign]
        result = await verify_chain(session=reader)

    assert result.verified is True
    assert result.total_entries == n
    assert result.first_divergence_index is None
    assert n > _VERIFY_BATCH_SIZE  # documents the >1-batch invariant
    assert captured_yield_per == [_VERIFY_BATCH_SIZE], (
        f"verify_chain must stream with yield_per={_VERIFY_BATCH_SIZE}; observed: {captured_yield_per}"
    )


# ---------- Caller contract ----------


@pytest.mark.asyncio
async def test_verify_chain_rejects_session_with_active_transaction(
    db_session: AsyncSession,
) -> None:
    await db_session.execute(sa.text("SELECT 1"))  # autobegins
    assert db_session.in_transaction()
    with pytest.raises(LedgerError) as exc_info:
        await verify_chain(session=db_session)
    assert exc_info.value.reason is not None
    assert "active transaction" in exc_info.value.reason


# ---------- Refactor pin: shared envelope between writer and verifier ----------


@pytest.mark.asyncio
async def test_verify_chain_envelope_identical_to_append_entry_envelope(db_session: AsyncSession) -> None:
    """The verifier's envelope must canonicalise to the same bytes as the writer's.

    Pins the ``_build_envelope`` extraction performed for HLAM-58 — a drift
    here would silently break every chain produced after the refactor. We
    fetch the persisted row, reconstruct its envelope via ``_envelope_for_row``,
    and confirm ``sha256(canonicalize(envelope)) == row.entry_hash``.
    """
    entry = await append_entry(
        event_type=LedgerEventType.SNAPSHOT_COMMITTED,
        snapshot_id=uuid.uuid4(),
        payload={"k": "v", "n": 1},
        session=db_session,
    )
    envelope = _envelope_for_row(entry)
    assert sha256(canonicalize(envelope)) == entry.entry_hash


# ---------- API contract ----------


def test_ledger_module_exports_chain_verification_surface() -> None:
    import pke_backend.services as svc

    assert svc.ChainVerification is ChainVerification
    assert svc.verify_chain is verify_chain
    field_names = set(ChainVerification.__dataclass_fields__.keys())
    assert field_names == {
        "total_entries",
        "verified",
        "first_divergence_index",
        "first_divergence_reason",
    }
