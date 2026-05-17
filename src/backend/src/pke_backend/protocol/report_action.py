"""Report-action protocol payload — abuse/legal flag for a snapshot.

Mirror of ``src/shared/schemas/report.json`` (HLAM-90). Distinct from
:mod:`pke_backend.protocol.report`, which owns the verifier's
``VerificationReport`` output type.

This module currently exposes the :class:`ReasonCategory` enum and the
``REPORT_VERSION`` constant needed by :mod:`pke_backend.models.report`. The
full Pydantic ``ReportAction`` wire shape is filled in by HLAM-78.

When HLAM-90 lands, ``shared/schemas/report.json`` must mirror the four
values declared in :class:`ReasonCategory` below.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

__all__ = ["REPORT_VERSION", "ReasonCategory"]

REPORT_VERSION: Final[str] = "0.1"


class ReasonCategory(StrEnum):
    ABUSE_CONCERN = "abuse_concern"
    LEGAL_REQUEST = "legal_request"
    OWNER_REQUEST = "owner_request"
    OTHER = "other"
