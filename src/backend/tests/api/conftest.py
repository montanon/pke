"""Shared fixtures + helpers for the API integration tests.

Originally HLAM-79 only; extended by HLAM-65/70/75/82 to:

* Truncate the full set of F1–F5 tables so a single test run can mix
  ``POST /reports``, ``POST /freezes``, ``GET /snapshots/{id}``,
  ``GET /snapshots/{id}/attestations``, and ``GET /key-grants`` without
  cross-test contamination.
* Seed snapshots together with their ``SNAPSHOT_COMMITTED`` ledger entry
  and an opaque blob on disk (the HLAM-65 metadata endpoint joins on the
  ledger entry; the blob endpoint streams from the BlobStore).
* Provide :func:`build_signed_report` / :func:`build_signed_freeze`, the
  signed-payload builders HLAM-82's "Implementation Notes" call
  ``make_signed_*``.

Engine-management pattern mirrors :mod:`tests.services.conftest`:

* Probe Postgres at the start of each test; skip if unreachable.
* Bring the schema up to ``head`` (migration tests may have left it at
  ``base``) before TRUNCATEing.
* Tests get a fresh :class:`sqlalchemy.ext.asyncio.AsyncSession` against
  the shared module-level engine in :mod:`pke_backend.db` and a fresh
  :class:`httpx.AsyncClient` against the FastAPI ``app``.
* Each test also gets its own :class:`FilesystemBlobStore` rooted at a
  ``tmp_path``-style temp dir, swapped in via
  :func:`pke_backend.services.blob_storage.reset_blob_store_cache`.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pke_backend.config import get_settings
from pke_backend.crypto.encoding import b64url_encode
from pke_backend.crypto.primitives.sign import sign as p256_sign
from pke_backend.db import dispose_engine, get_engine, get_sessionmaker
from pke_backend.main import app
from pke_backend.models import (
    CIPHERTEXT_HASH_BYTES,
    SESSION_NONCE_BYTES,
    SNAPSHOT_VERSION,
    EventType,
    KeyGrant,
    LedgerEntry,
    Snapshot,
    WitnessAttestation,
)
from pke_backend.protocol.freeze import FREEZE_VERSION, FreezeAction
from pke_backend.protocol.report_action import REPORT_VERSION, ReportAction
from pke_backend.services.blob_storage import (
    FilesystemBlobStore,
    reset_blob_store_cache,
)
from pke_backend.services.signing import canonical_signed_body

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _BACKEND_DIR / "alembic.ini"

# All API integration tables — TRUNCATE order doesn't matter under CASCADE.
_API_TABLES = (
    "freezes",
    "reports",
    "key_grants",
    "witness_attestations",
    "ledger_entries",
    "snapshots",
)


def _alembic_config() -> Config:
    cfg = Config(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", get_settings().DATABASE_URL)
    return cfg


async def _ensure_head() -> None:
    await asyncio.to_thread(command.upgrade, _alembic_config(), "head")


async def _probe_or_skip() -> None:
    engine = get_engine()
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover — environment dependent
        await dispose_engine()
        pytest.skip(f"postgres not reachable: {exc}")


def _uncompressed_pubkey_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


@pytest.fixture(autouse=True)
async def _hlam79_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[None]:
    """Reset DB tables + BlobStore singleton before/after each test.

    Disposes the module-level engine on both edges so each test binds to the
    current event loop (asyncpg connections cannot cross loops). Each test
    also gets its own BlobStore root under ``tmp_path`` — the singleton is
    invalidated via :func:`reset_blob_store_cache` so the next
    :func:`get_blob_store` call picks up the new root.
    """
    await dispose_engine()
    await _probe_or_skip()
    await _ensure_head()
    sm = get_sessionmaker()
    async with sm() as s:
        await s.execute(
            text(f"TRUNCATE TABLE {', '.join(_API_TABLES)} RESTART IDENTITY CASCADE"),
        )
        await s.commit()

    # Per-test BlobStore root: point Settings.BLOB_ROOT at a fresh dir via
    # the PKE_BLOB_ROOT env var, invalidate the Settings lru_cache, and the
    # BlobStore singleton so HLAM-65's endpoints see the new root.
    blob_root = tmp_path / "blobs"
    monkeypatch.setenv("PKE_BLOB_ROOT", str(blob_root))
    get_settings.cache_clear()
    reset_blob_store_cache()
    yield
    reset_blob_store_cache()
    get_settings.cache_clear()
    await dispose_engine()


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """One fresh ``AsyncSession`` per test for direct DB assertions."""
    sm = get_sessionmaker()
    async with sm() as s:
        yield s


@pytest.fixture
def owner_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
async def seed_snapshot_id(session: AsyncSession, owner_keypair: ec.EllipticCurvePrivateKey) -> uuid.UUID:
    """Insert a minimal :class:`Snapshot` row keyed to ``owner_keypair``.

    The owner's public key is stored on the row so a test can use
    ``owner_keypair`` to sign an owner-self-report.

    This fixture deliberately does **not** insert a ``SNAPSHOT_COMMITTED``
    ledger entry — the HLAM-79 POST tests expect their ``REPORTED`` write
    to be the first ledger row, and ``verify_hash_chain`` in
    ``test_report_freeze_e2e`` relies on that invariant. HLAM-65 / HLAM-82
    tests that need the join use :func:`seed_snapshot_with_blob` or insert
    a ``SNAPSHOT_COMMITTED`` row inline.
    """
    snapshot_id = uuid.uuid4()
    owner_pub = _uncompressed_pubkey_bytes(owner_keypair)
    snapshot = Snapshot(
        snapshot_id=snapshot_id,
        ciphertext_hash=b"\x11" * CIPHERTEXT_HASH_BYTES,
        owner_signing_public_key=owner_pub,
        owner_encryption_public_key=b"\x04" + b"\x33" * 64,
        capture_timestamp=datetime.now(tz=UTC),
        metadata_policy={"location_public": False, "media_type": "photo"},
        session_nonce=b"\x44" * SESSION_NONCE_BYTES,
        owner_signature=b"\x55" * 64,
        version=SNAPSHOT_VERSION,
        blob_storage_uri="s3://test/bucket/snapshot",
    )
    session.add(snapshot)
    await session.commit()
    return snapshot_id


async def seed_snapshot_with_blob(
    session: AsyncSession,
    blob_store: FilesystemBlobStore,
    *,
    content: bytes,
    owner_keypair: ec.EllipticCurvePrivateKey | None = None,
    ledger_entry_hash: bytes | None = None,
) -> tuple[uuid.UUID, bytes]:
    """Persist a snapshot + blob + ``SNAPSHOT_COMMITTED`` ledger entry.

    Used by HLAM-65 tests to assemble the joined invariants the GET
    endpoints assume. Returns ``(snapshot_id, ledger_entry_hash)``.
    """
    snapshot_id = uuid.uuid4()
    keypair = owner_keypair or ec.generate_private_key(ec.SECP256R1())
    owner_pub = _uncompressed_pubkey_bytes(keypair)
    ciphertext_hash = hashlib.sha256(content).digest()

    snapshot = Snapshot(
        snapshot_id=snapshot_id,
        ciphertext_hash=ciphertext_hash,
        owner_signing_public_key=owner_pub,
        owner_encryption_public_key=b"\x04" + b"\x77" * 64,
        capture_timestamp=datetime.now(tz=UTC),
        metadata_policy={"location_public": False, "media_type": "photo"},
        session_nonce=b"\xaa" * SESSION_NONCE_BYTES,
        owner_signature=b"\xbb" * 64,
        version=SNAPSHOT_VERSION,
        blob_storage_uri=f"file://blobs/{snapshot_id}/blob.bin",
    )
    session.add(snapshot)
    entry_hash = ledger_entry_hash if ledger_entry_hash is not None else b"\xcc" * 32
    session.add(
        LedgerEntry(
            ledger_entry_id=uuid.uuid4(),
            event_type=EventType.SNAPSHOT_COMMITTED,
            snapshot_id=snapshot_id,
            payload_hash=b"\xdd" * 32,
            previous_entry_hash=None,
            entry_hash=entry_hash,
            version="0.1",
        ),
    )
    await session.commit()

    async def _stream() -> AsyncIterator[bytes]:
        yield content

    await blob_store.put(snapshot_id, _stream())
    return snapshot_id, entry_hash


async def seed_attestation(
    session: AsyncSession,
    *,
    snapshot_id: uuid.UUID,
    witness_signing_public_key: str | None = None,
    transport: str = "bluetooth",
    ledger_entry_hash: bytes | None = None,
) -> tuple[WitnessAttestation, bytes]:
    """Insert a :class:`WitnessAttestation` + its WITNESS_ATTESTED ledger row.

    Both rows are inserted in the same transaction so HLAM-70's positional
    pairing in :func:`list_attestations` resolves cleanly.
    """
    witness_pub = witness_signing_public_key or b64url_encode(b"\x04" + b"\x66" * 64)
    attestation = WitnessAttestation(
        snapshot_id=snapshot_id,
        witness_signing_public_key=witness_pub,
        witness_timestamp=datetime.now(tz=UTC),
        transport=transport,
        proximity_claim={"method": "bluetooth-proximity", "exact_location_public": False},
        witness_signature=b"\x77" * 64,
        version="0.1",
    )
    session.add(attestation)
    entry_hash = ledger_entry_hash if ledger_entry_hash is not None else b"\x11" * 32
    session.add(
        LedgerEntry(
            ledger_entry_id=uuid.uuid4(),
            event_type=EventType.WITNESS_ATTESTED,
            snapshot_id=snapshot_id,
            payload_hash=b"\x22" * 32,
            previous_entry_hash=None,
            entry_hash=entry_hash,
            version="0.1",
        ),
    )
    await session.commit()
    return attestation, entry_hash


async def seed_key_grant(
    session: AsyncSession,
    *,
    snapshot_id: uuid.UUID,
    recipient_encryption_public_key: str,
    ledger_entry_hash: bytes | None = None,
) -> tuple[KeyGrant, bytes]:
    """Insert a :class:`KeyGrant` + its KEY_GRANTED ledger row."""
    grant = KeyGrant(
        grant_id=uuid.uuid4(),
        snapshot_id=snapshot_id,
        recipient_encryption_public_key=recipient_encryption_public_key,
        wrapped_snapshot_key=b"\x01" * 60,
        wrapping_algorithm="ecdhp256+aesgcm256",
        granted_by_signing_public_key=b64url_encode(b"\x04" + b"\x55" * 64),
        grant_timestamp=datetime.now(tz=UTC),
        grant_signature=b"\x44" * 64,
        version="0.1",
    )
    session.add(grant)
    entry_hash = ledger_entry_hash if ledger_entry_hash is not None else b"\x33" * 32
    session.add(
        LedgerEntry(
            ledger_entry_id=uuid.uuid4(),
            event_type=EventType.KEY_GRANTED,
            snapshot_id=snapshot_id,
            payload_hash=b"\x44" * 32,
            previous_entry_hash=None,
            entry_hash=entry_hash,
            version="0.1",
        ),
    )
    await session.commit()
    return grant, entry_hash


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def build_signed_report(
    *,
    snapshot_id: uuid.UUID,
    signer: ec.EllipticCurvePrivateKey,
    report_id: uuid.UUID | None = None,
    reason_category: str = "abuse_concern",
    report_timestamp: str = "2026-05-15T00:02:00Z",
) -> dict[str, Any]:
    """Build a wire-form dict for a signed Report, ready to POST."""
    pubkey = _uncompressed_pubkey_bytes(signer)
    rid = report_id if report_id is not None else uuid.uuid4()
    base: dict[str, Any] = {
        "type": "report",
        "version": REPORT_VERSION,
        "report_id": str(rid),
        "snapshot_id": str(snapshot_id),
        "reason_category": reason_category,
        "reported_by_signing_public_key": b64url_encode(pubkey),
        "report_timestamp": report_timestamp,
        "report_signature": b64url_encode(b"\x00" * 64),
    }
    action = ReportAction.model_validate(base)
    body = canonical_signed_body(action, "report_signature")
    sig = p256_sign(body, signer)
    base["report_signature"] = b64url_encode(sig)
    return base


def build_signed_freeze(
    *,
    snapshot_id: uuid.UUID,
    triggered_by: str,
    signer: ec.EllipticCurvePrivateKey,
    freeze_id: uuid.UUID | None = None,
    freeze_timestamp: str = "2026-05-15T00:02:05Z",
) -> dict[str, Any]:
    """Build a wire-form dict for a signed Freeze, ready to POST."""
    pubkey = _uncompressed_pubkey_bytes(signer)
    fid = freeze_id if freeze_id is not None else uuid.uuid4()
    base: dict[str, Any] = {
        "type": "freeze",
        "version": FREEZE_VERSION,
        "freeze_id": str(fid),
        "snapshot_id": str(snapshot_id),
        "triggered_by": triggered_by,
        "frozen_by_signing_public_key": b64url_encode(pubkey),
        "freeze_timestamp": freeze_timestamp,
        "freeze_signature": b64url_encode(b"\x00" * 64),
    }
    action = FreezeAction.model_validate(base)
    body = canonical_signed_body(action, "freeze_signature")
    sig = p256_sign(body, signer)
    base["freeze_signature"] = b64url_encode(sig)
    return base
