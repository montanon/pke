"""SQLAlchemy ORM models for the PKE backend.

Importing this package registers every declared model against
``pke_backend.db.Base.metadata`` so Alembic's autogenerate sees the full
schema. Keep new model modules listed here.
"""

from __future__ import annotations

from pke_backend.models.attestation import (
    WITNESS_ATTESTATION_VERSION,
    WitnessAttestation,
)
from pke_backend.models.freeze import FREEZE_VERSION, Freeze
from pke_backend.models.key_grant import KEY_GRANT_VERSION, KeyGrant
from pke_backend.models.ledger import LEDGER_VERSION, EventType, LedgerEntry
from pke_backend.models.report import REPORT_VERSION, ReasonCategory, Report
from pke_backend.models.snapshot import (
    CIPHERTEXT_HASH_BYTES,
    SESSION_NONCE_BYTES,
    SNAPSHOT_VERSION,
    Snapshot,
)

__all__ = [
    "CIPHERTEXT_HASH_BYTES",
    "FREEZE_VERSION",
    "KEY_GRANT_VERSION",
    "LEDGER_VERSION",
    "REPORT_VERSION",
    "SESSION_NONCE_BYTES",
    "SNAPSHOT_VERSION",
    "WITNESS_ATTESTATION_VERSION",
    "EventType",
    "Freeze",
    "KeyGrant",
    "LedgerEntry",
    "ReasonCategory",
    "Report",
    "Snapshot",
    "WitnessAttestation",
]
