"""Shared fixtures + helpers for HLAM-79 API integration tests.

Mirrors the engine-management pattern in :mod:`tests.services.conftest`:

* Probe Postgres at the start of each test; skip if unreachable.
* Bring the schema up to ``head`` (migration tests may have left it at
  ``base``) before TRUNCATEing the four HLAM-79 tables.
* Tests get a fresh :class:`sqlalchemy.ext.asyncio.AsyncSession` against the
  shared module-level engine in :mod:`pke_backend.db` and a fresh
  :class:`httpx.AsyncClient` against the FastAPI ``app``.

Also exposes :func:`build_signed_report` and :func:`build_signed_freeze` —
small wire-form-payload builders that sign the canonical body with a real
P-256 keypair so the resulting JSON is accepted by ``POST /reports`` /
``POST /freezes``.
"""

from __future__ import annotations

import asyncio
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
    Snapshot,
)
from pke_backend.protocol.freeze import FREEZE_VERSION, FreezeAction
from pke_backend.protocol.report_action import REPORT_VERSION, ReportAction
from pke_backend.services.signing import canonical_signed_body

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _BACKEND_DIR / "alembic.ini"

_HLAM79_TABLES = (
    "freezes",
    "reports",
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
async def _hlam79_clean() -> AsyncIterator[None]:
    """Reset HLAM-79-touched tables before/after each test.

    Disposes the module-level engine on both edges so each test binds to the
    current event loop (asyncpg connections cannot cross loops).
    """
    await dispose_engine()
    await _probe_or_skip()
    await _ensure_head()
    sm = get_sessionmaker()
    async with sm() as s:
        await s.execute(
            text(f"TRUNCATE TABLE {', '.join(_HLAM79_TABLES)} RESTART IDENTITY CASCADE"),
        )
        await s.commit()
    yield
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
async def seed_snapshot_id(
    session: AsyncSession, owner_keypair: ec.EllipticCurvePrivateKey
) -> uuid.UUID:
    """Insert a minimal :class:`Snapshot` row keyed to ``owner_keypair``.

    The owner's public key is stored on the row so a test can use
    ``owner_keypair`` to sign an owner-self-report.
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
