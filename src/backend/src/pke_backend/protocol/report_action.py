"""Report-action protocol payload — abuse/legal flag for a snapshot.

Mirror of ``src/shared/schemas/report.json`` (HLAM-90). Distinct from
:mod:`pke_backend.protocol.report`, which owns the verifier's
``VerificationReport`` output type.

This module exposes:

* :data:`REPORT_VERSION` — the locked v0.1 string used by both the Pydantic
  wire model and the ORM in :mod:`pke_backend.models.report`.
* :class:`ReasonCategory` — the 4-value enum re-exported by the ORM so the
  Python and DB enum stay byte-identical.
* :class:`ReportAction` — full Pydantic v2 wire model used by
  ``POST /reports`` for parse + canonical-bytes + signature verification.

The ``Base64UrlBytes`` typing on ``reported_by_signing_public_key`` and
``report_signature`` enforces unpadded base64url at decode time
(per ``context/16_canonical_encoding.md``) and emits the same form on
serialization, so ``to_json_value()`` is canonicalize-safe.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from pydantic import ConfigDict

from .types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime

__all__ = ["REPORT_VERSION", "ReasonCategory", "ReportAction"]

REPORT_VERSION: Final[str] = "0.1"


class ReasonCategory(StrEnum):
    ABUSE_CONCERN = "abuse_concern"
    LEGAL_REQUEST = "legal_request"
    OWNER_REQUEST = "owner_request"
    OTHER = "other"


class ReportAction(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    type: Literal["report"]
    # ``version`` is pinned to the locked v0.1 value per
    # ``context/16_canonical_encoding.md``: any mismatch would change the
    # canonical body, so the spec mandates explicit rejection.
    version: Literal["0.1"]
    report_id: str
    snapshot_id: str
    reason_category: ReasonCategory
    reported_by_signing_public_key: Base64UrlBytes
    report_timestamp: UTCDatetime
    report_signature: Base64UrlBytes
