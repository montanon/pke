"""Ledger entry protocol payload — mirror of `shared/schemas/ledger_entry.json`."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict

from .types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime

__all__ = ["LedgerEntry", "LedgerEventType"]


class LedgerEventType(StrEnum):
    SNAPSHOT_COMMITTED = "SNAPSHOT_COMMITTED"
    WITNESS_ATTESTED = "WITNESS_ATTESTED"
    KEY_GRANTED = "KEY_GRANTED"
    REPORTED = "REPORTED"
    FROZEN = "FROZEN"


class LedgerEntry(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    type: Literal["ledger_entry"]
    version: str
    ledger_entry_id: str
    event_type: LedgerEventType
    snapshot_id: str
    payload_hash: Base64UrlBytes
    previous_entry_hash: Base64UrlBytes
    entry_timestamp: UTCDatetime
    entry_hash: Base64UrlBytes
