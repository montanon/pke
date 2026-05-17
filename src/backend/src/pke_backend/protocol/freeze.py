"""Freeze-action protocol payload — restricts future key grants for a snapshot.

Mirror of ``src/shared/schemas/freeze.json`` (HLAM-90).

This module exposes:

* :data:`FREEZE_VERSION` — the locked v0.1 string used by both the Pydantic
  wire model and the ORM in :mod:`pke_backend.models.freeze`.
* :class:`FreezeAction` — full Pydantic v2 wire model used by
  ``POST /freezes`` for parse + canonical-bytes + signature verification.

The ``Base64UrlBytes`` typing on ``frozen_by_signing_public_key`` and
``freeze_signature`` enforces unpadded base64url at decode time
(per ``context/16_canonical_encoding.md``).

``triggered_by`` is an opaque protocol-level identifier (kept as ``str`` here
to match the JSON Schema). The service layer parses it to ``UUID`` and resolves
it against the ``reports`` table.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import ConfigDict

from .types import Base64UrlBytes, ToJsonValueMixin, UTCDatetime

__all__ = ["FREEZE_VERSION", "FreezeAction"]

FREEZE_VERSION: Final[str] = "0.1"


class FreezeAction(ToJsonValueMixin):
    model_config = ConfigDict(extra="forbid")
    type: Literal["freeze"]
    version: str
    freeze_id: str
    snapshot_id: str
    triggered_by: str
    frozen_by_signing_public_key: Base64UrlBytes
    freeze_timestamp: UTCDatetime
    freeze_signature: Base64UrlBytes
