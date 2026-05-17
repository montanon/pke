"""Custody-ledger service: append-only hash chain with advisory-lock concurrency.

This module implements the chain-construction primitive for HLAM-37. F2–F5
endpoint handlers call :func:`append_entry` to persist one custody event; the
service owns canonicalisation, chain hashing, and global write serialisation
so the handlers stay free of cryptographic detail.

Chain rule (locked at v0.1; see ``context/16_canonical_encoding.md``)::

    payload_hash         = SHA256(canonicalize(payload))
    envelope             = {type, version, ledger_entry_id, event_type,
                            snapshot_id, payload_hash, previous_entry_hash,
                            entry_timestamp}
    entry_hash           = SHA256(canonicalize(envelope))
    previous_entry_hash  = SQL NULL in the ORM for genesis; 32 zero bytes
                           in the canonical envelope and on the wire.

Concurrency model
-----------------

A Postgres transaction-scoped advisory lock (``pg_advisory_xact_lock``) keyed
by :data:`LEDGER_LOCK_KEY` serialises every writer. The lock is released
automatically at ``COMMIT`` or ``ROLLBACK``; no explicit unlock path exists.
The chain is global (not sharded by ``snapshot_id``) in MVP, which makes the
advisory lock the documented throughput ceiling. Future Features may shard.

Idempotency
-----------

The dedup key is ``(event_type, snapshot_id, payload_hash)``. A retry with an
identical canonical payload returns the existing row instead of allocating a
new one. The check runs twice inside the same transaction: once before
acquiring the advisory lock (an optimisation that skips the global writer
lock when a clean dedup hit is already visible) and once after, to close the
race against a concurrent writer that may have inserted the row while we were
waiting for the lock. The second check is what makes the design correct; the
first is purely an optimisation.

The dedup key is intentionally narrow. Callers MUST include enough
discriminating fields in ``payload`` that two semantically different events
for the same ``(event_type, snapshot_id)`` produce different canonical bytes
(and therefore different ``payload_hash`` values). For example, witness
attestations should include the attester identity or a nonce; a service that
re-submits ``{"reason": "frozen"}`` for two different freeze operators would
incorrectly dedupe to a single row. The service trusts the caller's payload
shape — it has no knowledge of which fields are semantically discriminating.

Caller contract
---------------

:func:`append_entry` opens its own transaction with ``async with session.begin()``.
The caller must therefore pass a session with **no active transaction**, which
is the natural state of a session returned from
:func:`pke_backend.db.get_session` (or any fresh ``async_sessionmaker()()``).
If the caller has issued prior reads on the same session, SQLAlchemy 2.0's
autobegin will have left an open transaction; in that case the caller must
``commit()`` or ``rollback()`` before invoking ``append_entry``.

Imports of the HLAM-2 canonicalisation/hashing helpers are unconditional —
there is intentionally no fallback. If the crypto package is unavailable this
module fails to import.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.errors import CanonicalEncodingError
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.types import JsonValue
from pke_backend.models.ledger import LEDGER_VERSION, LedgerEntry
from pke_backend.protocol.ledger import LedgerEventType

__all__ = [
    "LEDGER_LOCK_KEY",
    "ChainVerification",
    "LedgerCanonicalizationError",
    "LedgerError",
    "append_entry",
    "get_head",
    "verify_chain",
]

LEDGER_LOCK_KEY: Final[int] = 0x504B454C45444752
"""ASCII ``PKELEDGR`` packed into a Postgres ``bigint`` (signed 64-bit) advisory-lock key.

Postgres's ``pg_advisory_xact_lock(bigint)`` requires the key to fit in a
signed 64-bit integer (``< 2**63``). The value above is ``2**63 - 1``-safe
(``5_786_684_238_083_053_394``); future keys for sibling chains must respect
the same bound.
"""

_GENESIS_PREVIOUS_ENTRY_HASH: Final[bytes] = b"\x00" * 32

_ENTRY_HASH_BYTES: Final[int] = 32

_LEDGER_ENTRY_ENVELOPE_TYPE: Final[str] = "ledger_entry"

_VERIFY_BATCH_SIZE: Final[int] = 256
"""Cursor batch size for :func:`verify_chain`.

Chosen so each ``fetchmany`` round trip carries enough rows to amortise its
cost without keeping more than ~256 ORM rows resident at once. The streaming
test pins the contract by asserting the statement passed to
:meth:`AsyncSession.stream` carries ``yield_per`` equal to this value — that
is what proves the verifier is actually streaming rather than materialising
the table in one fetch.
"""


class LedgerError(Exception):
    __slots__ = ("reason",)

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason

    def __str__(self) -> str:
        if self.reason is None:
            return type(self).__name__
        return f"{type(self).__name__}: {self.reason}"


class LedgerCanonicalizationError(LedgerError):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Result of :func:`verify_chain`.

    ``verified`` is ``True`` iff every entry's recomputed ``entry_hash``
    matches the stored value and every ``previous_entry_hash`` links to the
    prior row (or is SQL NULL on the genesis row).

    On failure, ``first_divergence_index`` is the 0-based position in the
    ``ORDER BY id ASC`` walk where the first inconsistency was detected, and
    ``first_divergence_reason`` is a short, content-free explanation. Both
    fields are ``None`` on success.

    ``total_entries`` is the row count observed by a separate ``SELECT
    count(*)`` issued before the stream begins. Under concurrent inserts the
    count may lag the latest committed row; the integrity verdict itself
    remains correct because the stream walk and the count both run under
    Postgres read-committed isolation within the same session.
    """

    total_entries: int
    verified: bool
    first_divergence_index: int | None
    first_divergence_reason: str | None


_UTC_OFFSET_SUFFIX_LEN: Final[int] = len("+00:00")


def _serialize_utc_z(value: datetime) -> str:
    """Render ``value`` as Z-suffixed ISO-8601 in UTC.

    Defensively normalises ``value`` to UTC first (via ``astimezone(UTC)``):
    even though the service generates ``datetime.now(UTC)`` itself, callers
    that re-load ledger rows from Postgres and pass them through this helper
    must get a deterministic wire form regardless of the local tzinfo asyncpg
    happens to attach. Naive datetimes (``tzinfo is None``) are rejected so
    that an unintended local-time leak can never silently corrupt the chain.
    """
    if value.tzinfo is None:
        raise LedgerError(reason="entry_timestamp must be timezone-aware")
    utc_value = value.astimezone(UTC)
    iso = utc_value.isoformat()
    if iso.endswith("+00:00"):
        return iso[:-_UTC_OFFSET_SUFFIX_LEN] + "Z"
    return iso


def _build_envelope(
    *,
    version: str,
    ledger_entry_id: uuid.UUID,
    event_type: LedgerEventType,
    snapshot_id: uuid.UUID,
    payload_hash: bytes,
    previous_entry_hash_bytes: bytes,
    entry_timestamp: datetime,
) -> dict[str, JsonValue]:
    """Construct the canonical ledger-entry envelope shared by writer and verifier.

    The caller passes ``previous_entry_hash_bytes`` already substituted for
    genesis (32 zero bytes) when the row has a SQL ``NULL``; this helper
    performs no NULL handling itself. Keeping the call sites identical between
    :func:`append_entry` (writer) and :func:`_envelope_for_row` (verifier) is
    what binds the chain rule by code rather than by convention.
    """
    return {
        "type": _LEDGER_ENTRY_ENVELOPE_TYPE,
        "version": version,
        "ledger_entry_id": str(ledger_entry_id),
        "event_type": event_type.value,
        "snapshot_id": str(snapshot_id),
        "payload_hash": b64url_encode(payload_hash),
        "previous_entry_hash": b64url_encode(previous_entry_hash_bytes),
        "entry_timestamp": _serialize_utc_z(entry_timestamp),
    }


def _envelope_for_row(row: LedgerEntry) -> dict[str, JsonValue]:
    """Rebuild the canonical envelope for a persisted ``LedgerEntry`` row.

    Mirrors :func:`append_entry`'s envelope construction byte-for-byte. The
    only transformation is the genesis substitution: a SQL ``NULL`` in
    ``previous_entry_hash`` becomes 32 zero bytes for canonicalisation.
    """
    previous_bytes = row.previous_entry_hash if row.previous_entry_hash is not None else _GENESIS_PREVIOUS_ENTRY_HASH
    return _build_envelope(
        version=row.version,
        ledger_entry_id=row.ledger_entry_id,
        event_type=row.event_type,
        snapshot_id=row.snapshot_id,
        payload_hash=row.payload_hash,
        previous_entry_hash_bytes=previous_bytes,
        entry_timestamp=row.entry_timestamp,
    )


async def _lookup_by_dedup_key(
    session: AsyncSession,
    *,
    event_type: LedgerEventType,
    snapshot_id: uuid.UUID,
    payload_hash: bytes,
) -> LedgerEntry | None:
    stmt = (
        select(LedgerEntry)
        .where(
            LedgerEntry.event_type == event_type,
            LedgerEntry.snapshot_id == snapshot_id,
            LedgerEntry.payload_hash == payload_hash,
        )
        .order_by(LedgerEntry.id.asc())
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def _read_head(session: AsyncSession) -> LedgerEntry | None:
    stmt = select(LedgerEntry).order_by(LedgerEntry.id.desc()).limit(1)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_head(*, session: AsyncSession) -> LedgerEntry | None:
    """Return the most recent ledger entry by primary-key order, or ``None`` if empty."""
    return await _read_head(session)


async def append_entry(
    *,
    event_type: LedgerEventType,
    snapshot_id: uuid.UUID,
    payload: JsonValue,
    version: str = LEDGER_VERSION,
    session: AsyncSession,
) -> LedgerEntry:
    """Append one custody event to the ledger and return the persisted row.

    The session must not already be inside a transaction; the service owns
    the transaction so the advisory lock is held for the full append-or-dedup
    critical section and is released at commit/rollback.
    """
    if session.in_transaction():
        raise LedgerError(
            reason=("session must not have an active transaction; commit or rollback before calling append_entry"),
        )

    try:
        payload_hash = sha256(canonicalize(payload))
    except CanonicalEncodingError as exc:
        raise LedgerCanonicalizationError(reason=exc.reason) from exc

    async with session.begin():
        existing = await _lookup_by_dedup_key(
            session,
            event_type=event_type,
            snapshot_id=snapshot_id,
            payload_hash=payload_hash,
        )
        if existing is not None:
            return existing

        await session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"),
            {"key": LEDGER_LOCK_KEY},
        )

        existing = await _lookup_by_dedup_key(
            session,
            event_type=event_type,
            snapshot_id=snapshot_id,
            payload_hash=payload_hash,
        )
        if existing is not None:
            return existing

        prior = await _read_head(session)
        previous_entry_hash_for_envelope = prior.entry_hash if prior is not None else _GENESIS_PREVIOUS_ENTRY_HASH
        previous_entry_hash_for_orm: bytes | None = prior.entry_hash if prior is not None else None

        ledger_entry_id = uuid.uuid4()
        now_utc = datetime.now(UTC)

        envelope = _build_envelope(
            version=version,
            ledger_entry_id=ledger_entry_id,
            event_type=event_type,
            snapshot_id=snapshot_id,
            payload_hash=payload_hash,
            previous_entry_hash_bytes=previous_entry_hash_for_envelope,
            entry_timestamp=now_utc,
        )
        entry_hash = sha256(canonicalize(envelope))

        entry = LedgerEntry(
            ledger_entry_id=ledger_entry_id,
            event_type=event_type,
            snapshot_id=snapshot_id,
            payload_hash=payload_hash,
            previous_entry_hash=previous_entry_hash_for_orm,
            entry_timestamp=now_utc,
            entry_hash=entry_hash,
            version=version,
        )
        session.add(entry)
        await session.flush()
        return entry


async def verify_chain(
    *,
    session: AsyncSession,
    snapshot_id: uuid.UUID | None = None,
) -> ChainVerification:
    """Replay the global ledger chain and report integrity.

    Streams every row in ``ORDER BY id ASC`` using an async cursor with
    ``yield_per=_VERIFY_BATCH_SIZE`` so memory stays bounded regardless of
    table size. For each row:

    1. Confirms the stored ``entry_hash`` is exactly :data:`_ENTRY_HASH_BYTES`
       bytes (defensive — the column is ``LargeBinary(32)`` UNIQUE, so this
       is virtually unreachable through ordinary writes).
    2. Recomputes ``sha256(canonicalize(envelope))`` from the row's persisted
       fields via :func:`_envelope_for_row` (byte-identical to the writer
       path) and compares it to the stored ``entry_hash``.
    3. Confirms ``previous_entry_hash`` linkage: SQL ``NULL`` at the genesis
       index 0, otherwise equal to the prior row's stored ``entry_hash``.

    The first divergence stops the walk and is returned via the
    ``first_divergence_*`` fields of :class:`ChainVerification`. The function
    never raises on chain integrity failures — that is the design distinction
    from :func:`pke_backend.crypto.hashing.verify_hash_chain`, which raises.
    F6's verification report needs the divergence index in its response, not
    in an exception handler.

    The ``snapshot_id`` parameter is **informational only** and never narrows
    the integrity walk: the chain is globally linear, so a per-snapshot view
    of an intact chain must always reflect the full chain's verdict. The
    parameter is reserved for a future return-shape that includes a
    per-snapshot summary projection (out of scope here; HLAM-42 will own
    that projection in the endpoint layer).

    Caller contract mirrors :func:`append_entry`: the session must not have
    an active transaction. ``verify_chain`` issues its own reads under
    Postgres default read-committed isolation.

    Concurrent writers that commit during the walk may add rows past the
    cursor; those are not seen by the current call. ``total_entries`` is
    captured by a separate ``SELECT count(*)`` before the stream begins and
    may therefore lag the latest committed insert under contention.
    """
    if session.in_transaction():
        raise LedgerError(
            reason="session must not have an active transaction; commit or rollback before calling verify_chain",
        )

    # Accepted but unused at runtime: reserved for a future return-shape that
    # projects per-snapshot entries from the global walk (see docstring §6 and
    # the Phase-1 design comment on the Jira story). Kept as a kwarg now so
    # HLAM-42 does not break the signature when it begins consuming it.
    _ = snapshot_id

    try:
        count_stmt = select(func.count()).select_from(LedgerEntry)
        total = int((await session.execute(count_stmt)).scalar_one())
        if total == 0:
            return ChainVerification(
                total_entries=0,
                verified=True,
                first_divergence_index=None,
                first_divergence_reason=None,
            )

        stmt = select(LedgerEntry).order_by(LedgerEntry.id.asc()).execution_options(yield_per=_VERIFY_BATCH_SIZE)

        prior_entry_hash: bytes | None = None
        index = 0
        stream = await session.stream(stmt)
        async for row in stream.scalars():
            if len(row.entry_hash) != _ENTRY_HASH_BYTES:
                return ChainVerification(
                    total_entries=total,
                    verified=False,
                    first_divergence_index=index,
                    first_divergence_reason=(
                        f"entry_hash at index {index} has invalid length: {len(row.entry_hash)} (expected {_ENTRY_HASH_BYTES})"
                    ),
                )

            try:
                envelope = _envelope_for_row(row)
                recomputed = sha256(canonicalize(envelope))
            except CanonicalEncodingError as exc:
                # Programming errors (e.g. _serialize_utc_z's naive-datetime
                # guard) intentionally propagate as LedgerError rather than
                # being softened into a verification verdict — DB-loaded
                # TIMESTAMPTZ values are always tz-aware in practice.
                return ChainVerification(
                    total_entries=total,
                    verified=False,
                    first_divergence_index=index,
                    first_divergence_reason=f"failed to canonicalize entry at index {index}: {exc}",
                )

            if recomputed != row.entry_hash:
                return ChainVerification(
                    total_entries=total,
                    verified=False,
                    first_divergence_index=index,
                    first_divergence_reason=f"entry_hash mismatch at index {index}",
                )

            if index == 0:
                if row.previous_entry_hash is not None:
                    return ChainVerification(
                        total_entries=total,
                        verified=False,
                        first_divergence_index=0,
                        first_divergence_reason="genesis must have NULL previous_entry_hash",
                    )
            elif row.previous_entry_hash != prior_entry_hash:
                return ChainVerification(
                    total_entries=total,
                    verified=False,
                    first_divergence_index=index,
                    first_divergence_reason=f"previous_entry_hash mismatch at index {index}",
                )

            prior_entry_hash = row.entry_hash
            index += 1

        return ChainVerification(
            total_entries=total,
            verified=True,
            first_divergence_index=None,
            first_divergence_reason=None,
        )
    finally:
        # Release the autobegun read transaction. A long-lived session passed
        # by a CLI tool or batch caller would otherwise hold a read txn open
        # until the next user action — cheap to clean up, expensive to leak.
        if session.in_transaction():
            await session.rollback()
