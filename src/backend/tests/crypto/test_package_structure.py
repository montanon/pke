from __future__ import annotations

import importlib

import pytest

HELPER_MODULES = (
    "canonicalize",
    "encoding",
    "hashing",
    "signatures",
    "kdf",
    "errors",
    "types",
)

PRIMITIVE_MODULES = ("sign", "aead", "keywrap")


def test_crypto_package_importable() -> None:
    pkg = importlib.import_module("pke_backend.crypto")
    assert pkg.__all__, "pke_backend.crypto.__all__ must be non-empty"


@pytest.mark.parametrize("name", HELPER_MODULES)
def test_helper_modules_present(name: str) -> None:
    importlib.import_module(f"pke_backend.crypto.{name}")


@pytest.mark.parametrize("name", PRIMITIVE_MODULES)
def test_primitive_modules_present(name: str) -> None:
    importlib.import_module(f"pke_backend.crypto.primitives.{name}")


def test_cryptography_ec_import_resolves() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    assert ec.SECP256R1.__name__ == "SECP256R1"
