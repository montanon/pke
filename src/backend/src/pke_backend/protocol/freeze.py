"""Freeze-action protocol payload — restricts future key grants for a snapshot.

Mirror of ``src/shared/schemas/freeze.json`` (HLAM-90). This module currently
exposes only the ``FREEZE_VERSION`` constant needed by
:mod:`pke_backend.models.freeze`. The full Pydantic ``FreezeAction`` wire
shape is filled in by HLAM-78.
"""

from __future__ import annotations

from typing import Final

__all__ = ["FREEZE_VERSION"]

FREEZE_VERSION: Final[str] = "0.1"
