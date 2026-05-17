"""Defense-in-depth: walk every production module under ``pke_backend.api`` and
``pke_backend.services`` and fail if anything imports ``pke_backend.crypto.primitives``.

This test runs independently of the ruff banned-api rule so that accidental
removal of either layer does not silently re-open the boundary.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import pke_backend

_BANNED_PREFIX = "pke_backend.crypto.primitives"
_PACKAGE_ROOT = Path(pke_backend.__file__).resolve().parent
_SCOPED_DIRS: tuple[Path, ...] = (
    _PACKAGE_ROOT / "api",
    _PACKAGE_ROOT / "services",
)


def _is_banned(dotted: str | None) -> bool:
    if dotted is None:
        return False
    return dotted == _BANNED_PREFIX or dotted.startswith(_BANNED_PREFIX + ".")


def _scan_file(path: Path) -> list[tuple[Path, int, str]]:
    """Return ``(path, lineno, dotted_name)`` for every banned import in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders: list[tuple[Path, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_banned(alias.name):
                    offenders.append((path, node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            if _is_banned(module):
                offenders.append((path, node.lineno, module or ""))
            elif module is not None:
                for alias in node.names:
                    candidate = f"{module}.{alias.name}"
                    if _is_banned(candidate):
                        offenders.append((path, node.lineno, candidate))
    return offenders


def _iter_production_files() -> Iterator[Path]:
    for root in _SCOPED_DIRS:
        if not root.exists():
            continue
        yield from sorted(root.rglob("*.py"))


def test_scoped_directories_exist() -> None:
    for root in _SCOPED_DIRS:
        assert root.is_dir(), f"expected production directory {root}"


def test_production_code_does_not_import_primitives() -> None:
    files = list(_iter_production_files())
    assert files, "expected at least one production .py file (api/services)"

    all_offenders: list[tuple[Path, int, str]] = []
    for path in files:
        all_offenders.extend(_scan_file(path))

    if all_offenders:
        rendered = "\n".join(
            f"  {path.relative_to(_PACKAGE_ROOT.parent.parent)}:{lineno} imports {name}"
            for path, lineno, name in all_offenders
        )
        pytest.fail(
            f"Production code must not import {_BANNED_PREFIX}.*; offenders:\n{rendered}",
        )


def test_planted_stub_is_caught(tmp_path: Path) -> None:
    """Synthetic mirror of AC #3/#5: an injected ``import`` is detected."""
    stub = tmp_path / "health.py"
    stub.write_text("import pke_backend.crypto.primitives.sign\n", encoding="utf-8")
    offenders = _scan_file(stub)
    assert offenders, "AST walker must detect a planted import"
    assert offenders[0][2] == "pke_backend.crypto.primitives.sign"


def test_planted_from_import_is_caught(tmp_path: Path) -> None:
    stub = tmp_path / "health.py"
    stub.write_text(
        "from pke_backend.crypto.primitives import sign as s  # noqa: F401\n",
        encoding="utf-8",
    )
    offenders = _scan_file(stub)
    assert offenders, "AST walker must detect a from-import"


def test_planted_from_submodule_import_is_caught(tmp_path: Path) -> None:
    stub = tmp_path / "health.py"
    stub.write_text(
        "from pke_backend.crypto.primitives.aead import encrypt  # noqa: F401\n",
        encoding="utf-8",
    )
    offenders = _scan_file(stub)
    assert offenders, "AST walker must detect a sub-module from-import"


def test_aliased_import_is_caught(tmp_path: Path) -> None:
    stub = tmp_path / "health.py"
    stub.write_text(
        "import pke_backend.crypto.primitives.keywrap as kw  # noqa: F401\n",
        encoding="utf-8",
    )
    offenders = _scan_file(stub)
    assert offenders, "AST walker must detect aliased imports"


def test_unrelated_crypto_import_is_permitted(tmp_path: Path) -> None:
    stub = tmp_path / "ok.py"
    stub.write_text(
        "from pke_backend.crypto import canonicalize  # noqa: F401\n"
        "from pke_backend.crypto.hashing import sha256  # noqa: F401\n",
        encoding="utf-8",
    )
    assert _scan_file(stub) == []
