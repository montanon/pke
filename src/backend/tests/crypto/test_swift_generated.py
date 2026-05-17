"""Symmetric loader for Swift-generated test vectors.

Enumerates every JSON file under ``src/shared/test_vectors/swift_generated/``
and re-runs the corresponding Python primitive to assert byte-for-byte parity
(positive cases) or rejection (negative cases). Mirrors the bundle shape and
field schema emitted by ``src/shared/tools/generate_vectors.py`` so a hand-
authored Swift bundle dropped into ``swift_generated/<primitive>/`` is verified
on the next CI run with no test-side changes.

When the placeholder directory contains no vectors the test skips cleanly
(HLAM-33 AC 6 / Edge Case 2). An unknown primitive directory fails fast with
a clear message (HLAM-33 Edge Case 3).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.errors import AEADError, SignatureVerificationError
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.kdf import hkdf_sha256
from pke_backend.crypto.primitives.aead import aead_seal
from pke_backend.crypto.primitives.keywrap import unwrap_snapshot_key, wrap_snapshot_key
from pke_backend.crypto.signatures import verify_signature

SWIFT_GENERATED_DIR = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "swift_generated"


# ---------------------------------------------------------------------------
# Bundle shape validation
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = ("name", "inputs", "expected", "valid")


def _load_bundle(path: Path) -> dict[str, Any]:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(bundle, dict):
        pytest.fail(f"{path}: top-level value must be a JSON object, got {type(bundle).__name__}")
    for key in _REQUIRED_KEYS:
        if key not in bundle:
            pytest.fail(f"{path}: missing required top-level key {key!r}")
    if not isinstance(bundle["inputs"], dict) or not isinstance(bundle["expected"], dict):
        pytest.fail(f"{path}: 'inputs' and 'expected' must be objects")
    if not isinstance(bundle["valid"], bool):
        pytest.fail(f"{path}: 'valid' must be a boolean")
    return bundle


# ---------------------------------------------------------------------------
# Per-primitive verifiers
#
# Each verifier mirrors the field schema emitted by the corresponding
# emitter in ``src/shared/tools/generate_vectors.py``. For positive bundles
# the verifier asserts byte-for-byte equality with ``expected``. For
# negative bundles the verifier asserts the documented rejection signal
# (mismatch, exception, or decoder error).
#
# Every assertion message embeds ``path`` so a failure inside a multi-vector
# CI run points unambiguously at the offending file.
# ---------------------------------------------------------------------------


def _verify_canonical_json(bundle: dict[str, Any], path: Path) -> None:
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    if bundle["valid"]:
        canonical_hex = canonicalize(inputs["value"]).hex()
        assert canonical_hex == expected["canonical_bytes_hex"], (
            f"{path}: canonical_bytes mismatch — expected {expected['canonical_bytes_hex']}, got {canonical_hex}"
        )
        return
    # Negative: the documented schema is `inputs.raw_utf8_hex` plus
    # `expected.error == "duplicate_key"`, exercising decoder rejection.
    if "raw_utf8_hex" not in inputs:
        pytest.fail(
            f"{path}: canonical_json negative bundle missing 'raw_utf8_hex' — "
            f"only the duplicate-key rejection shape is currently supported",
        )
    raw = bytes.fromhex(str(inputs["raw_utf8_hex"]))

    def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({k for k, _ in pairs}) != len(pairs):
            raise ValueError("duplicate_key")
        return dict(pairs)

    with pytest.raises(ValueError, match="duplicate_key"):
        json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_hook)


def _verify_sha256(bundle: dict[str, Any], path: Path) -> None:
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    actual_hex = sha256(bytes.fromhex(str(inputs["message_hex"]))).hex()
    expected_hex = str(expected["digest_hex"])
    if bundle["valid"]:
        assert actual_hex == expected_hex, f"{path}: sha256 digest mismatch — expected {expected_hex}, got {actual_hex}"
    else:
        assert actual_hex != expected_hex, (
            f"{path}: sha256 negative bundle expected divergence but digest matched {actual_hex}"
        )


def _verify_ecdsa_p256(bundle: dict[str, Any], path: Path) -> None:
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    pub_raw = bytes.fromhex(str(inputs["public_key_uncompressed_hex"]))
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_raw)
    message = bytes.fromhex(str(inputs["message_hex"]))
    sig = bytes.fromhex(str(expected["signature_p1363_hex"]))
    if bundle["valid"]:
        assert verify_signature(pub, message, sig) is None, f"{path}: ecdsa_p256 positive bundle failed to verify"
        return
    try:
        verify_signature(pub, message, sig)
    except SignatureVerificationError:
        return
    pytest.fail(f"{path}: ecdsa_p256 negative bundle did not raise SignatureVerificationError")


def _verify_hkdf_sha256(bundle: dict[str, Any], path: Path) -> None:
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    snapshot_id_bytes = str(inputs["snapshot_id"]).encode("utf-8")
    recipient_pub = bytes.fromhex(str(inputs["recipient_public_key_hex"]))
    salt = bytes.fromhex(str(expected["salt_hex"]))
    info = (
        b"pke/v0.1/keywrap/info"
        + len(snapshot_id_bytes).to_bytes(2, "big")
        + snapshot_id_bytes
        + len(recipient_pub).to_bytes(2, "big")
        + recipient_pub
    )
    computed_info_hex = info.hex()
    okm_hex = hkdf_sha256(bytes.fromhex(str(inputs["ikm_hex"])), salt, info, 32).hex()
    if bundle["valid"]:
        assert computed_info_hex == expected["info_hex"], (
            f"{path}: hkdf info mismatch — expected {expected['info_hex']}, got {computed_info_hex}"
        )
        assert okm_hex == expected["okm_hex"], (
            f"{path}: hkdf okm mismatch — expected {expected['okm_hex']}, got {okm_hex}"
        )
    else:
        # Negative: at least one of (info, okm) must diverge from expected. The
        # Python generator's pattern mutates info_hex while keeping okm_hex
        # correct, but a Swift-generated negative could legitimately mutate
        # either or both — accept any divergence as "negative case surfaced".
        assert computed_info_hex != expected["info_hex"] or okm_hex != expected["okm_hex"], (
            f"{path}: hkdf negative bundle expected divergence in info or okm but both matched"
        )


def _verify_aes_gcm(bundle: dict[str, Any], path: Path) -> None:
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    key = bytes.fromhex(str(inputs["key_hex"]))
    nonce = bytes.fromhex(str(inputs["nonce_hex"]))
    aad = bytes.fromhex(str(inputs["aad_hex"]))
    plaintext = bytes.fromhex(str(inputs["plaintext_hex"]))
    sealed = aead_seal(plaintext, key, nonce, aad)
    ciphertext_hex = sealed[:-16].hex()
    tag_hex = sealed[-16:].hex()
    if bundle["valid"]:
        assert ciphertext_hex == expected["ciphertext_hex"], (
            f"{path}: aes-gcm ciphertext mismatch — expected {expected['ciphertext_hex']}, got {ciphertext_hex}"
        )
        assert tag_hex == expected["tag_hex"], (
            f"{path}: aes-gcm tag mismatch — expected {expected['tag_hex']}, got {tag_hex}"
        )
    else:
        assert tag_hex != expected["tag_hex"] or ciphertext_hex != expected["ciphertext_hex"], (
            f"{path}: aes-gcm negative bundle expected divergence but ciphertext+tag both matched"
        )


def _verify_ecdh_wrap(bundle: dict[str, Any], path: Path) -> None:
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    snapshot_id = str(inputs["snapshot_id"])
    snapshot_key = bytes.fromhex(str(inputs["snapshot_key_hex"]))
    sender_priv = serialization.load_pem_private_key(
        str(inputs["sender_private_key_pkcs8_pem"]).encode("ascii"),
        password=None,
    )
    recipient_priv = serialization.load_pem_private_key(
        str(inputs["recipient_private_key_pkcs8_pem"]).encode("ascii"),
        password=None,
    )
    if not isinstance(sender_priv, ec.EllipticCurvePrivateKey) or not isinstance(
        recipient_priv, ec.EllipticCurvePrivateKey
    ):
        pytest.fail(f"{path}: ecdh_wrap sender/recipient PEMs must decode to EC private keys")
    nonce = bytes.fromhex(str(inputs["aead_nonce_hex"]))
    recomputed_wrapped = wrap_snapshot_key(
        snapshot_key,
        sender_priv,
        recipient_priv.public_key(),
        snapshot_id,
        nonce=nonce,
    ).hex()
    if bundle["valid"]:
        assert recomputed_wrapped == expected["wrapped_key_hex"], (
            f"{path}: ecdh_wrap wrapped_key mismatch — expected {expected['wrapped_key_hex']}, got {recomputed_wrapped}"
        )
        unwrapped = unwrap_snapshot_key(
            bytes.fromhex(recomputed_wrapped),
            recipient_priv,
            sender_priv.public_key(),
            snapshot_id,
        )
        assert unwrapped == snapshot_key, f"{path}: ecdh_wrap round-trip did not recover the original snapshot_key"
        return
    # Negative: bundle's expected.wrapped_key_hex is corrupted; unwrap must fail.
    try:
        unwrap_snapshot_key(
            bytes.fromhex(str(expected["wrapped_key_hex"])),
            recipient_priv,
            sender_priv.public_key(),
            snapshot_id,
        )
    except AEADError:
        return
    pytest.fail(f"{path}: ecdh_wrap negative bundle did not raise AEADError on unwrap")


def _verify_hash_chain(bundle: dict[str, Any], path: Path) -> None:
    inputs = bundle["inputs"]
    expected = bundle["expected"]
    chain = inputs["chain"]
    if not isinstance(chain, list):
        pytest.fail(f"{path}: hash_chain inputs.chain must be a list, got {type(chain).__name__}")
    computed = [sha256(canonicalize(entry)).hex() for entry in chain]
    expected_hashes = list(expected["entry_hashes_hex"])
    if bundle["valid"]:
        assert computed == expected_hashes, (
            f"{path}: hash_chain entry hashes mismatch — expected={expected_hashes}, got={computed}"
        )
        return
    diverge_indices = [i for i, (a, b) in enumerate(zip(computed, expected_hashes)) if a != b]
    assert diverge_indices, f"{path}: hash_chain negative bundle expected divergence but every entry hash matched"
    if "broken_at_index" in expected:
        assert diverge_indices[0] == int(expected["broken_at_index"]), (
            f"{path}: hash_chain negative — first divergence at index {diverge_indices[0]} "
            f"!= expected broken_at_index {expected['broken_at_index']}"
        )


VERIFIERS: dict[str, Callable[[dict[str, Any], Path], None]] = {
    "canonical_json": _verify_canonical_json,
    "sha256": _verify_sha256,
    "ecdsa_p256": _verify_ecdsa_p256,
    "hkdf_sha256": _verify_hkdf_sha256,
    "aes_gcm": _verify_aes_gcm,
    "ecdh_wrap": _verify_ecdh_wrap,
    "hash_chain": _verify_hash_chain,
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def test_swift_generated_placeholder_directory_exists() -> None:
    """Guards AC 5 — the placeholder directory must be committed."""
    assert SWIFT_GENERATED_DIR.is_dir(), f"{SWIFT_GENERATED_DIR} is missing — commit a .gitkeep placeholder."


def test_swift_generated_vectors_verify() -> None:
    """Enumerate Swift-generated vectors and verify each with Python.

    Skips cleanly when the placeholder directory is empty (AC 6 /
    Edge Case 2). Dispatches by parent-directory name; unknown primitive
    directories fail fast (Edge Case 3).
    """
    paths = sorted(SWIFT_GENERATED_DIR.rglob("*.json"))
    if not paths:
        pytest.skip("No Swift-generated vectors yet — placeholder directory is empty")
    for path in paths:
        primitive = path.parent.name
        verifier = VERIFIERS.get(primitive)
        if verifier is None:
            pytest.fail(
                f"{path}: no verifier registered for primitive directory {primitive!r}. "
                f"Known primitives: {sorted(VERIFIERS)}",
            )
        bundle = _load_bundle(path)
        verifier(bundle, path)
