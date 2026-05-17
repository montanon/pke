"""Protocol-version test for ``pke_backend.protocol.freeze`` (HLAM-77)."""

from __future__ import annotations

from pke_backend.protocol import freeze
from pke_backend.protocol.freeze import FREEZE_VERSION


def test_freeze_version_constant() -> None:
    assert FREEZE_VERSION == "0.1"


def test_freeze_module_exports_public_symbols() -> None:
    assert "FREEZE_VERSION" in freeze.__all__
