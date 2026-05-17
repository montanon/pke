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
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select, text
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
    "LedgerCanonicalizationError",
    "LedgerError",
    "append_entry",
    "get_head",
]

LEDGER_LOCK_KEY: Final[int] = 0x504B454C45444752
"""ASCII ``PKELEDGR`` packed into a Postgres ``bigint`` (signed 64-bit) advisory-lock key.

Postgres's ``pg_advisory_xact_lock(bigint)`` requires the key to fit in a
signed 64-bit integer (``< 2**63``). The value above is ``2**63 - 1``-safe
(``5_786_684_238_083_053_394``); future keys for sibling chains must respect
the same bound.
"""

_GENESIS_PREVIOUS_ENTRY_HASH: Final[bytes] = b"\x00" * 32

_LEDGER_ENTRY_ENVELOPE_TYPE: Final[str] = "ledger_entry"


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

        envelope: dict[str, JsonValue] = {
            "type": _LEDGER_ENTRY_ENVELOPE_TYPE,
            "version": version,
            "ledger_entry_id": str(ledger_entry_id),
            "event_type": event_type.value,
            "snapshot_id": str(snapshot_id),
            "payload_hash": b64url_encode(payload_hash),
            "previous_entry_hash": b64url_encode(previous_entry_hash_for_envelope),
            "entry_timestamp": _serialize_utc_z(now_utc),
        }
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
