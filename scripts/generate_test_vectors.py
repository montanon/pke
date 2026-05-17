"""Generate cross-implementation test vectors for PKE primitives.

This script produces deterministic JSON test-vector bundles under
``src/shared/test_vectors/`` covering seven cryptographic primitives:
canonical JSON, SHA-256, ECDSA P-256, HKDF-SHA256, AES-256-GCM,
ECDH+AESGCM key wrap, and the ledger hash chain.

The output is byte-identical across runs: all keys, nonces, and
inputs are derived from a hard-coded seed via SHA-256. After writing
files, the script self-checks the produced bundles and exits non-zero
on any failure.

Re-run with::

    /path/to/.venv/bin/python scripts/generate_test_vectors.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Layout & constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_ROOT = REPO_ROOT / "src" / "shared" / "test_vectors"

HKDF_SALT = b"pke/v0.1/keywrap/salt"
HKDF_INFO_PREFIX = b"pke/v0.1/keywrap/info"
AAD_PREFIX = b"pke/v0.1/keywrap/aad"

# NIST P-256 group order n; scalars are reduced mod (n - 1) and incremented
# by 1 so that 0 is impossible.
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

SEED = b"pke/v0.1/test-vectors/seed/2026-05-16"

DIRS = (
    "canonical_json",
    "sha256",
    "ecdsa_p256",
    "hkdf_sha256",
    "aes_gcm",
    "ecdh_wrap",
    "hash_chain",
)


# ---------------------------------------------------------------------------
# Determinism helpers
# ---------------------------------------------------------------------------


def _det_bytes(label: str, length: int = 32) -> bytes:
    """Deterministically derive ``length`` bytes from the seed + label."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(SEED + label.encode("utf-8") + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _det_scalar(label: str) -> int:
    """Deterministic non-zero scalar in [1, n-1] for P-256."""
    raw = int.from_bytes(_det_bytes("scalar/" + label, 32), "big")
    return (raw % (P256_N - 1)) + 1


def _det_p256_private(label: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(_det_scalar(label), ec.SECP256R1())


def _pem_pkcs8(private_key: ec.EllipticCurvePrivateKey) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


def _uncompressed_public_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return raw.hex()


def _uncompressed_public_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def keywrap_info(snapshot_id: str, recipient_pub_raw: bytes) -> bytes:
    sid = snapshot_id.encode("utf-8")
    return (
        HKDF_INFO_PREFIX
        + len(sid).to_bytes(2, "big")
        + sid
        + len(recipient_pub_raw).to_bytes(2, "big")
        + recipient_pub_raw
    )


def keywrap_aad(snapshot_id: str) -> bytes:
    sid = snapshot_id.encode("utf-8")
    return AAD_PREFIX + len(sid).to_bytes(2, "big") + sid


def ecdsa_sign_p1363(private_key: ec.EllipticCurvePrivateKey, message: bytes, k_seed: bytes | None = None) -> bytes:
    """Sign and convert DER -> raw P1363 (64 bytes)."""
    # cryptography's deterministic-by-default-or-randomized sign emits DER;
    # we just call sign() — but since cryptography uses RFC 6979 deterministic
    # ECDSA via its OpenSSL backend? Actually OpenSSL ECDSA is randomized.
    # For determinism we use an explicit deterministic-k via the private key
    # value: hash (msg||sk) to derive a deterministic signature is not what
    # we want either. Easier path: sign once with cryptography (randomized),
    # then verify; pin the result by writing the produced signature into the
    # fixture. But that's not byte-stable across runs.
    #
    # We need bytes-stable signatures across runs. Cryptography exposes
    # deterministic ECDSA via ec.ECDSA(hashes.SHA256()) — but that's still
    # randomized via OpenSSL. So we implement deterministic ECDSA ourselves
    # using a fixed k derived from (sk, message).
    del k_seed
    sk_int = private_key.private_numbers().private_value
    h = int.from_bytes(hashlib.sha256(message).digest(), "big")
    # Deterministic k per RFC 6979 (simplified): k = HMAC-SHA256-based; but
    # cryptography lacks a direct hook. We instead derive k from a hash of
    # (sk, h) and reject k = 0 by retry.
    counter = 0
    while True:
        k_material = hashlib.sha256(
            b"pke/v0.1/test-vectors/k/"
            + sk_int.to_bytes(32, "big")
            + h.to_bytes(32, "big")
            + counter.to_bytes(4, "big")
        ).digest()
        k = (int.from_bytes(k_material, "big") % (P256_N - 1)) + 1
        # Compute R = k*G; r = R.x mod n
        priv_k = ec.derive_private_key(k, ec.SECP256R1())
        r = priv_k.public_key().public_numbers().x % P256_N
        if r == 0:
            counter += 1
            continue
        # Modular inverse of k mod n
        k_inv = pow(k, -1, P256_N)
        s = (k_inv * (h + r * sk_int)) % P256_N
        if s == 0:
            counter += 1
            continue
        # Low-s normalization (BIP-style) — not strictly required by FIPS 186-4
        # but makes signatures canonical and avoids ambiguity.
        if s > P256_N // 2:
            s = P256_N - s
        # Verify the signature using cryptography to sanity-check.
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        der = encode_dss_signature(r, s)
        try:
            private_key.public_key().verify(der, message, ec.ECDSA(hashes.SHA256()))
        except Exception:
            counter += 1
            continue
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def ecdsa_verify_p1363(public_key_uncompressed: bytes, message: bytes, sig_p1363: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if len(sig_p1363) != 64:
        return False
    r = int.from_bytes(sig_p1363[:32], "big")
    s = int.from_bytes(sig_p1363[32:], "big")
    der = encode_dss_signature(r, s)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_uncompressed)
    try:
        pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# File writer
# ---------------------------------------------------------------------------


def write_bundle(directory: str, file_stem: str, bundle: dict[str, Any]) -> Path:
    out_dir = VECTORS_ROOT / directory
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{file_stem}.json"
    text = json.dumps(bundle, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    path.write_text(text, encoding="utf-8")
    return path


def flip_hex_byte(hex_str: str, byte_offset: int) -> tuple[str, int]:
    """Flip exactly one byte (XOR 0x01) at the given byte offset in a hex string.

    Returns the mutated hex string and the byte offset used.
    """
    raw = bytearray.fromhex(hex_str)
    raw[byte_offset] ^= 0x01
    return raw.hex(), byte_offset


# ---------------------------------------------------------------------------
# Generators per primitive
# ---------------------------------------------------------------------------


def gen_canonical_json() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    # p1: empty object
    val: Any = {}
    cases.append(
        (
            "p1-empty-object",
            {
                "name": "p1-empty-object",
                "inputs": {"value": val},
                "expected": {"canonical_bytes_hex": canonical_json(val).hex()},
                "valid": True,
            },
        )
    )

    # p2: flat object with mixed value types (sorted keys)
    val = {"b": 2, "a": "x", "c": True}
    cases.append(
        (
            "p2-flat-mixed",
            {
                "name": "p2-flat-mixed",
                "inputs": {"value": val},
                "expected": {"canonical_bytes_hex": canonical_json(val).hex()},
                "valid": True,
                "notes": "Keys must sort lexicographically: a, b, c.",
            },
        )
    )

    # p3: nested objects with arrays
    val = {
        "outer": {"y": [1, 2, {"z": "deep", "a": None}], "x": False},
        "alpha": "first",
    }
    cases.append(
        (
            "p3-nested-arrays",
            {
                "name": "p3-nested-arrays",
                "inputs": {"value": val},
                "expected": {"canonical_bytes_hex": canonical_json(val).hex()},
                "valid": True,
                "notes": "Nested key ordering applies recursively; array order is preserved.",
            },
        )
    )

    # p4: unicode (non-ASCII emitted as UTF-8 bytes, not \uXXXX)
    val = {"name": "café", "city": "São Paulo", "symbol": "→"}
    cases.append(
        (
            "p4-unicode",
            {
                "name": "p4-unicode",
                "inputs": {"value": val},
                "expected": {"canonical_bytes_hex": canonical_json(val).hex()},
                "valid": True,
                "notes": "ensure_ascii=False — non-ASCII characters are emitted as raw UTF-8 bytes.",
            },
        )
    )

    # Negative: duplicate-key rejection. The raw UTF-8 hex carries a JSON
    # document with two entries for the same key at the same level.
    raw = b'{"a":1,"a":2}'
    cases.append(
        (
            "n1-duplicate-key",
            {
                "name": "n1-duplicate-key",
                "inputs": {"raw_utf8_hex": raw.hex()},
                "expected": {"error": "duplicate_key"},
                "valid": False,
                "notes": (
                    "Decoder MUST reject documents with duplicate keys at the same level. "
                    "Per HLAM-3 canonical-JSON rules, duplicate keys are invalid on decode."
                ),
            },
        )
    )

    return cases


def gen_sha256() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    msgs = [
        ("p1-empty", b""),
        ("p2-short-abc", b"abc"),
        ("p3-longer-synthetic", _det_bytes("sha256/p3", 256)),
    ]
    for stem, msg in msgs:
        digest = hashlib.sha256(msg).hexdigest()
        cases.append(
            (
                stem,
                {
                    "name": stem,
                    "inputs": {"message_hex": msg.hex()},
                    "expected": {"digest_hex": digest},
                    "valid": True,
                },
            )
        )

    # Negative: clone p2 inputs, flip one byte in the expected digest.
    sibling_msg = b"abc"
    correct_digest = hashlib.sha256(sibling_msg).hexdigest()
    mutated_digest, offset = flip_hex_byte(correct_digest, 7)
    cases.append(
        (
            "n1-mutated-digest",
            {
                "name": "n1-mutated-digest",
                "inputs": {"message_hex": sibling_msg.hex()},
                "expected": {"digest_hex": mutated_digest},
                "valid": False,
                "notes": (
                    f"Sibling positive: p2-short-abc. expected.digest_hex byte at offset {offset} flipped "
                    "(XOR 0x01); implementation hashing inputs.message_hex will NOT match."
                ),
            },
        )
    )

    return cases


def gen_ecdsa_p256() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    payloads = [
        ("p1-snapshot-commit", b'{"kind":"snapshot","seq":1}'),
        ("p2-attestation", b'{"kind":"attestation","seq":42,"hash":"abc"}'),
        ("p3-binary-payload", _det_bytes("ecdsa/p3", 128)),
    ]
    sigs_by_stem: dict[str, str] = {}
    for stem, msg in payloads:
        sk = _det_p256_private("ecdsa/" + stem)
        pub_hex = _uncompressed_public_hex(sk)
        sig = ecdsa_sign_p1363(sk, msg)
        assert ecdsa_verify_p1363(bytes.fromhex(pub_hex), msg, sig), "self-verify failed"
        sigs_by_stem[stem] = sig.hex()
        cases.append(
            (
                stem,
                {
                    "name": stem,
                    "inputs": {
                        "private_key_pkcs8_pem": _pem_pkcs8(sk),
                        "public_key_uncompressed_hex": pub_hex,
                        "message_hex": msg.hex(),
                    },
                    "expected": {"signature_p1363_hex": sig.hex()},
                    "valid": True,
                    "notes": "Deterministic ECDSA with low-s normalization for byte-stable test vectors.",
                },
            )
        )

    # Negative: clone p1, flip one byte of the signature.
    sibling_stem = "p1-snapshot-commit"
    sibling_case = next(c for s, c in cases if s == sibling_stem)
    mutated_sig, offset = flip_hex_byte(sibling_case["expected"]["signature_p1363_hex"], 33)
    cases.append(
        (
            "n1-flipped-signature",
            {
                "name": "n1-flipped-signature",
                "inputs": dict(sibling_case["inputs"]),
                "expected": {"signature_p1363_hex": mutated_sig},
                "valid": False,
                "notes": (
                    f"Sibling positive: {sibling_stem}. expected.signature_p1363_hex byte at offset {offset} "
                    "flipped (XOR 0x01); verification MUST fail."
                ),
            },
        )
    )

    return cases


# Three named recipient keys used across HKDF and ECDH-wrap fixtures so the
# inter-primitive narrative (snapshot_id binds info; same snapshot, different
# recipient -> different wrapping_key) is reproducible.
def _named_recipient(label: str) -> ec.EllipticCurvePrivateKey:
    return _det_p256_private("recipient/" + label)


def gen_hkdf_sha256() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    R1 = _named_recipient("R1")
    R2 = _named_recipient("R2")
    R1_pub = _uncompressed_public_bytes(R1)
    R2_pub = _uncompressed_public_bytes(R2)

    ikm = _det_bytes("hkdf/ikm", 32)

    triples = [
        ("p1-snap0001-r1", "snap-0001", R1_pub),
        ("p2-snap0001-r2", "snap-0001", R2_pub),
        ("p3-snap0002-r1", "snap-0002", R1_pub),
    ]
    p1_info_hex = ""
    p1_okm_hex = ""
    p1_inputs: dict[str, Any] = {}
    for stem, sid, rpub in triples:
        info = keywrap_info(sid, rpub)
        okm = hkdf_sha256(ikm, HKDF_SALT, info, 32)
        inputs = {
            "ikm_hex": ikm.hex(),
            "snapshot_id": sid,
            "recipient_public_key_hex": rpub.hex(),
        }
        expected = {
            "salt_hex": HKDF_SALT.hex(),
            "info_hex": info.hex(),
            "okm_hex": okm.hex(),
        }
        cases.append(
            (
                stem,
                {
                    "name": stem,
                    "inputs": inputs,
                    "expected": expected,
                    "valid": True,
                    "notes": (
                        "HKDF-SHA256 with salt=b'pke/v0.1/keywrap/salt' and length-prefixed info per "
                        "HLAM-3 canonical-encoding spec."
                    ),
                },
            )
        )
        if stem == "p1-snap0001-r1":
            p1_info_hex = info.hex()
            p1_okm_hex = okm.hex()
            p1_inputs = inputs

    # Sanity: all three okm differ.
    okm_set = {c["expected"]["okm_hex"] for _, c in cases}
    assert len(okm_set) == 3, "HKDF positives must produce distinct okm"

    # Negative: clone p1 inputs, mutate one byte of expected.info_hex.
    mutated_info, offset = flip_hex_byte(p1_info_hex, 5)
    cases.append(
        (
            "n1-wrong-info-bytes",
            {
                "name": "n1-wrong-info-bytes",
                "inputs": dict(p1_inputs),
                "expected": {
                    "salt_hex": HKDF_SALT.hex(),
                    "info_hex": mutated_info,
                    "okm_hex": p1_okm_hex,
                },
                "valid": False,
                "notes": (
                    f"Sibling positive: p1-snap0001-r1. expected.info_hex byte at offset {offset} "
                    "flipped (XOR 0x01) while expected.okm_hex retains the correct value. "
                    "An implementation that ingests inputs and constructs info per the HLAM-3 spec "
                    "will produce expected.okm_hex but its computed info_hex will NOT match the "
                    "(deliberately corrupted) expected.info_hex — surfacing the mismatch."
                ),
            },
        )
    )

    return cases


def gen_aes_gcm() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    triples = [
        (
            "p1-empty-aad",
            _det_bytes("aesgcm/p1/key", 32),
            _det_bytes("aesgcm/p1/nonce", 12),
            b"",
            b"hello world",
        ),
        (
            "p2-real-aad",
            _det_bytes("aesgcm/p2/key", 32),
            _det_bytes("aesgcm/p2/nonce", 12),
            b"pke/v0.1/keywrap/aad\x00\x09snap-XYZA",
            _det_bytes("aesgcm/p2/pt", 32),
        ),
        (
            "p3-larger-plaintext",
            _det_bytes("aesgcm/p3/key", 32),
            _det_bytes("aesgcm/p3/nonce", 12),
            b"context/v1",
            _det_bytes("aesgcm/p3/pt", 1024),
        ),
    ]
    p2_inputs: dict[str, Any] = {}
    p2_tag_hex = ""
    p2_ct_hex = ""
    for stem, key, nonce, aad, pt in triples:
        aead = AESGCM(key)
        ct_and_tag = aead.encrypt(nonce, pt, aad)
        ct = ct_and_tag[: len(pt)]
        tag = ct_and_tag[len(pt) :]
        assert len(tag) == 16, "tag length"
        inputs = {
            "key_hex": key.hex(),
            "nonce_hex": nonce.hex(),
            "aad_hex": aad.hex(),
            "plaintext_hex": pt.hex(),
        }
        expected = {"ciphertext_hex": ct.hex(), "tag_hex": tag.hex()}
        cases.append(
            (
                stem,
                {
                    "name": stem,
                    "inputs": inputs,
                    "expected": expected,
                    "valid": True,
                    "notes": "Nonce is fixed for determinism; production code MUST use a random nonce.",
                },
            )
        )
        if stem == "p2-real-aad":
            p2_inputs = inputs
            p2_tag_hex = tag.hex()
            p2_ct_hex = ct.hex()

    # Negative: clone p2, flip one byte in expected.tag_hex.
    mutated_tag, offset = flip_hex_byte(p2_tag_hex, 4)
    cases.append(
        (
            "n1-corrupted-tag",
            {
                "name": "n1-corrupted-tag",
                "inputs": dict(p2_inputs),
                "expected": {"ciphertext_hex": p2_ct_hex, "tag_hex": mutated_tag},
                "valid": False,
                "notes": (
                    f"Sibling positive: p2-real-aad. expected.tag_hex byte at offset {offset} flipped "
                    "(XOR 0x01); AES-GCM tag verification MUST fail on decrypt."
                ),
            },
        )
    )

    return cases


def gen_ecdh_wrap() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    sender = _det_p256_private("ecdh/sender")
    R1 = _named_recipient("R1")
    R2 = _named_recipient("R2")

    snapshot_id = "snap-shared"
    snapshot_key = _det_bytes("ecdh/snapshot_key", 32)
    nonce = _det_bytes("ecdh/aead_nonce", 12)
    aad = keywrap_aad(snapshot_id)

    triples = [("p1-snapshared-r1", R1), ("p2-snapshared-r2", R2)]
    p1_wrapped_hex = ""
    p1_inputs: dict[str, Any] = {}
    p1_expected: dict[str, Any] = {}
    seen_wrapping_keys: set[str] = set()
    for stem, recipient in triples:
        shared = sender.exchange(ec.ECDH(), recipient.public_key())
        rpub_raw = _uncompressed_public_bytes(recipient)
        info = keywrap_info(snapshot_id, rpub_raw)
        wkey = hkdf_sha256(shared, HKDF_SALT, info, 32)
        seen_wrapping_keys.add(wkey.hex())
        aead = AESGCM(wkey)
        ct_and_tag = aead.encrypt(nonce, snapshot_key, aad)
        wrapped = nonce + ct_and_tag
        assert len(wrapped) == 60, f"wrapped key must be 60 bytes, got {len(wrapped)}"

        inputs = {
            "snapshot_id": snapshot_id,
            "snapshot_key_hex": snapshot_key.hex(),
            "sender_private_key_pkcs8_pem": _pem_pkcs8(sender),
            "sender_public_key_uncompressed_hex": _uncompressed_public_hex(sender),
            "recipient_private_key_pkcs8_pem": _pem_pkcs8(recipient),
            "recipient_public_key_uncompressed_hex": rpub_raw.hex(),
            "aead_nonce_hex": nonce.hex(),
        }
        expected = {
            "shared_secret_hex": shared.hex(),
            "hkdf_info_hex": info.hex(),
            "hkdf_aad_hex": aad.hex(),
            "wrapping_key_hex": wkey.hex(),
            "wrapped_key_hex": wrapped.hex(),
        }
        cases.append(
            (
                stem,
                {
                    "name": stem,
                    "inputs": inputs,
                    "expected": expected,
                    "valid": True,
                    "notes": (
                        "End-to-end ecdhp256+aesgcm256 wrap. AEAD nonce is fixed for determinism; "
                        "production code MUST use a random 12-byte nonce per encryption."
                    ),
                },
            )
        )
        if stem == "p1-snapshared-r1":
            p1_wrapped_hex = wrapped.hex()
            p1_inputs = inputs
            p1_expected = expected

    assert len(seen_wrapping_keys) == 2, (
        "Two ecdh_wrap positives with same snapshot_id and different recipients MUST produce "
        "distinct wrapping keys; got duplicates."
    )

    # Negative: clone p1, flip one byte of expected.wrapped_key_hex.
    mutated_wrapped, offset = flip_hex_byte(p1_wrapped_hex, 30)
    neg_expected = dict(p1_expected)
    neg_expected["wrapped_key_hex"] = mutated_wrapped
    cases.append(
        (
            "n1-corrupted-wrapped-key",
            {
                "name": "n1-corrupted-wrapped-key",
                "inputs": dict(p1_inputs),
                "expected": neg_expected,
                "valid": False,
                "notes": (
                    f"Sibling positive: p1-snapshared-r1. expected.wrapped_key_hex byte at offset {offset} "
                    "flipped (XOR 0x01); AEAD tag verification MUST fail on unwrap."
                ),
            },
        )
    )

    return cases


def _entry_hash(entry: dict[str, Any]) -> bytes:
    return hashlib.sha256(canonical_json(entry)).digest()


def _build_chain(length: int, label: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Return (chain entries, entry_hashes_hex) for a chain of given length."""
    entries: list[dict[str, Any]] = []
    hashes_hex: list[str] = []
    prev = b"\x00" * 32
    for i in range(length):
        payload_hash = hashlib.sha256(
            f"{label}/payload/{i}".encode() + _det_bytes(f"hash_chain/{label}/{i}", 16)
        ).digest()
        entry = {
            "seq": i,
            "payload_hash_hex": payload_hash.hex(),
            "previous_entry_hash_hex": prev.hex(),
        }
        h = _entry_hash(entry)
        entries.append(entry)
        hashes_hex.append(h.hex())
        prev = h
    return entries, hashes_hex


def gen_hash_chain() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    for stem, length in [("p1-len1", 1), ("p2-len2", 2), ("p3-len5", 5)]:
        chain, hashes_hex = _build_chain(length, stem)
        cases.append(
            (
                stem,
                {
                    "name": stem,
                    "inputs": {"chain": chain},
                    "expected": {"entry_hashes_hex": hashes_hex},
                    "valid": True,
                    "notes": (
                        "entry_hash[i] = SHA256(canonical_json(entry_i)); entry_i includes "
                        "previous_entry_hash_hex which is entry_hash[i-1] (or 32 zero bytes for genesis)."
                    ),
                },
            )
        )

    # Negative: clone p3, mutate middle link (index 2) payload_hash_hex by one byte.
    sibling_chain, sibling_hashes = _build_chain(5, "p3-len5")
    mutated_chain = [dict(e) for e in sibling_chain]
    mutated_payload, offset = flip_hex_byte(mutated_chain[2]["payload_hash_hex"], 11)
    mutated_chain[2]["payload_hash_hex"] = mutated_payload
    cases.append(
        (
            "n1-mutated-middle-link",
            {
                "name": "n1-mutated-middle-link",
                "inputs": {"chain": mutated_chain},
                "expected": {"entry_hashes_hex": sibling_hashes, "broken_at_index": 2},
                "valid": False,
                "notes": (
                    f"Sibling positive: p3-len5. inputs.chain[2].payload_hash_hex byte at offset {offset} "
                    "flipped (XOR 0x01). expected.entry_hashes_hex retains the original chain's hashes; "
                    "an implementation recomputing entry_hash over the mutated chain will diverge starting "
                    "at index 2 (broken_at_index)."
                ),
            },
        )
    )

    return cases


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


GENERATORS = {
    "canonical_json": gen_canonical_json,
    "sha256": gen_sha256,
    "ecdsa_p256": gen_ecdsa_p256,
    "hkdf_sha256": gen_hkdf_sha256,
    "aes_gcm": gen_aes_gcm,
    "ecdh_wrap": gen_ecdh_wrap,
    "hash_chain": gen_hash_chain,
}


def write_all() -> dict[str, list[Path]]:
    written: dict[str, list[Path]] = {}
    # Wipe any existing JSON files in each directory so a previous run with
    # different file names does not leave stragglers.
    for d in DIRS:
        out_dir = VECTORS_ROOT / d
        out_dir.mkdir(parents=True, exist_ok=True)
        for old in sorted(out_dir.glob("*.json")):
            old.unlink()
    for d, gen in GENERATORS.items():
        paths: list[Path] = []
        for stem, bundle in gen():
            paths.append(write_bundle(d, stem, bundle))
        written[d] = paths
    return written


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

HEX_ALPHABET = set("0123456789abcdef")


def is_lowercase_hex(s: str) -> bool:
    if len(s) % 2 != 0:
        return False
    return all(c in HEX_ALPHABET for c in s)


def _walk_hex_fields(obj: Any, path: str = "") -> list[tuple[str, str]]:
    """Yield (path, value) for every key ending in '_hex' that is a string."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else k
            if isinstance(v, str) and (k.endswith("_hex") or k == "raw_utf8_hex"):
                out.append((sub, v))
            else:
                out.extend(_walk_hex_fields(v, sub))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            out.extend(_walk_hex_fields(item, f"{path}[{i}]"))
    return out


def _check_bundle_shape(bundle: dict[str, Any], file: Path) -> list[str]:
    errors: list[str] = []
    required = {"name", "inputs", "expected", "valid"}
    missing = required - bundle.keys()
    if missing:
        errors.append(f"{file}: missing top-level keys: {sorted(missing)}")
    extra = set(bundle.keys()) - (required | {"notes"})
    if extra:
        errors.append(f"{file}: unexpected top-level keys: {sorted(extra)}")
    if not isinstance(bundle.get("name"), str):
        errors.append(f"{file}: 'name' must be string")
    if not isinstance(bundle.get("inputs"), dict):
        errors.append(f"{file}: 'inputs' must be object")
    if not isinstance(bundle.get("expected"), dict):
        errors.append(f"{file}: 'expected' must be object")
    if not isinstance(bundle.get("valid"), bool):
        errors.append(f"{file}: 'valid' must be boolean")
    if "notes" in bundle and not isinstance(bundle["notes"], str):
        errors.append(f"{file}: 'notes' must be string when present")
    for fp, val in _walk_hex_fields(bundle):
        if not is_lowercase_hex(val):
            errors.append(f"{file}: hex field {fp!r} is not lowercase hex: {val[:40]!r}")
    return errors


def _check_length(bundle: dict[str, Any], file: Path) -> list[str]:
    errors: list[str] = []
    inp = bundle.get("inputs", {})
    exp = bundle.get("expected", {})
    # SHA-256 digest length (when present).
    if "digest_hex" in exp:
        if len(exp["digest_hex"]) != 64:
            errors.append(f"{file}: digest_hex must be 64 chars; got {len(exp['digest_hex'])}")
    # ECDSA signature.
    if "signature_p1363_hex" in exp:
        if len(exp["signature_p1363_hex"]) != 128:
            errors.append(f"{file}: signature_p1363_hex must be 128 chars")
    # P-256 uncompressed pubkey.
    for key in (
        "public_key_uncompressed_hex",
        "recipient_public_key_hex",
        "sender_public_key_uncompressed_hex",
        "recipient_public_key_uncompressed_hex",
    ):
        if key in inp and len(inp[key]) != 130:
            errors.append(f"{file}: {key} must be 130 chars; got {len(inp[key])}")
    # AES-256 key.
    if "key_hex" in inp and len(inp["key_hex"]) != 64:
        errors.append(f"{file}: key_hex must be 64 chars")
    if "nonce_hex" in inp and len(inp["nonce_hex"]) != 24:
        errors.append(f"{file}: nonce_hex must be 24 chars")
    if "tag_hex" in exp and len(exp["tag_hex"]) != 32:
        errors.append(f"{file}: tag_hex must be 32 chars")
    if "wrapping_key_hex" in exp and len(exp["wrapping_key_hex"]) != 64:
        errors.append(f"{file}: wrapping_key_hex must be 64 chars")
    if "shared_secret_hex" in exp and len(exp["shared_secret_hex"]) != 64:
        errors.append(f"{file}: shared_secret_hex must be 64 chars")
    if "wrapped_key_hex" in exp and len(exp["wrapped_key_hex"]) != 120:
        errors.append(f"{file}: wrapped_key_hex must be 120 chars (60 bytes); got {len(exp['wrapped_key_hex'])}")
    if "okm_hex" in exp and len(exp["okm_hex"]) != 64:
        errors.append(f"{file}: okm_hex must be 64 chars")
    return errors


def _diff_byte_count(a_hex: str, b_hex: str) -> int:
    if len(a_hex) != len(b_hex):
        return -1
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    return sum(1 for x, y in zip(a, b, strict=False) if x != y)


NEGATIVE_SIBLINGS: dict[str, tuple[str, str, str]] = {
    # primitive_dir -> (negative_stem, sibling_stem, field_path_in_bundle)
    # field path uses dot notation rooted at the bundle dict.
    "sha256": ("n1-mutated-digest", "p2-short-abc", "expected.digest_hex"),
    "ecdsa_p256": ("n1-flipped-signature", "p1-snapshot-commit", "expected.signature_p1363_hex"),
    "hkdf_sha256": ("n1-wrong-info-bytes", "p1-snap0001-r1", "expected.info_hex"),
    "aes_gcm": ("n1-corrupted-tag", "p2-real-aad", "expected.tag_hex"),
    "ecdh_wrap": ("n1-corrupted-wrapped-key", "p1-snapshared-r1", "expected.wrapped_key_hex"),
    # hash_chain handled specially (mutation is inside an array of dicts).
}


def _resolve_path(obj: dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        cur = cur[part]
    return cur


def self_check() -> int:
    errors: list[str] = []
    counts: dict[str, dict[str, int]] = {}
    for d in DIRS:
        out_dir = VECTORS_ROOT / d
        files = sorted(out_dir.glob("*.json"))
        pos = 0
        neg = 0
        for f in files:
            try:
                bundle = json.loads(f.read_text("utf-8"))
            except json.JSONDecodeError as e:
                errors.append(f"{f}: JSON decode error: {e}")
                continue
            errors.extend(_check_bundle_shape(bundle, f))
            errors.extend(_check_length(bundle, f))
            if bundle.get("valid") is True:
                pos += 1
            elif bundle.get("valid") is False:
                neg += 1

        counts[d] = {"positive": pos, "negative": neg, "total": len(files)}

    # Cross-check: every negative differs from designated sibling by exactly one byte.
    for d, (neg_stem, sib_stem, field_path) in NEGATIVE_SIBLINGS.items():
        neg_file = VECTORS_ROOT / d / f"{neg_stem}.json"
        sib_file = VECTORS_ROOT / d / f"{sib_stem}.json"
        if not neg_file.exists() or not sib_file.exists():
            errors.append(f"{d}: missing negative or sibling file")
            continue
        neg_b = json.loads(neg_file.read_text("utf-8"))
        sib_b = json.loads(sib_file.read_text("utf-8"))
        neg_val = _resolve_path(neg_b, field_path)
        sib_val = _resolve_path(sib_b, field_path)
        diff = _diff_byte_count(sib_val, neg_val)
        if diff != 1:
            errors.append(
                f"{d}: negative {neg_stem!r} field {field_path!r} differs from sibling {sib_stem!r} "
                f"by {diff} bytes (must be exactly 1)"
            )

    # hash_chain special: middle-link mutation inside chain[2].payload_hash_hex.
    neg_file = VECTORS_ROOT / "hash_chain" / "n1-mutated-middle-link.json"
    sib_file = VECTORS_ROOT / "hash_chain" / "p3-len5.json"
    if neg_file.exists() and sib_file.exists():
        neg_b = json.loads(neg_file.read_text("utf-8"))
        sib_b = json.loads(sib_file.read_text("utf-8"))
        neg_payload = neg_b["inputs"]["chain"][2]["payload_hash_hex"]
        sib_payload = sib_b["inputs"]["chain"][2]["payload_hash_hex"]
        diff = _diff_byte_count(sib_payload, neg_payload)
        if diff != 1:
            errors.append(
                f"hash_chain: negative chain[2].payload_hash_hex differs from p3-len5 by {diff} bytes "
                "(must be exactly 1)"
            )
        # Also confirm OTHER chain entries are unchanged.
        for i, (n_entry, s_entry) in enumerate(zip(neg_b["inputs"]["chain"], sib_b["inputs"]["chain"], strict=True)):
            if i == 2:
                # payload_hash differs by 1 byte; previous_entry_hash and seq must be identical.
                if n_entry["seq"] != s_entry["seq"]:
                    errors.append("hash_chain neg: seq mutated at index 2")
                if n_entry["previous_entry_hash_hex"] != s_entry["previous_entry_hash_hex"]:
                    errors.append("hash_chain neg: previous_entry_hash_hex mutated at index 2")
            elif n_entry != s_entry:
                errors.append(f"hash_chain neg: entry at index {i} unexpectedly differs from sibling")
    else:
        errors.append("hash_chain: missing negative or sibling file for cross-check")

    # AC #4: empty SHA-256 digest.
    empty_file = VECTORS_ROOT / "sha256" / "p1-empty.json"
    if empty_file.exists():
        b = json.loads(empty_file.read_text("utf-8"))
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        if b["expected"]["digest_hex"] != expected:
            errors.append(f"sha256 p1-empty digest mismatch: {b['expected']['digest_hex']}")

    # AC #6: ecdh_wrap p1 and p2 share snapshot_id, distinct wrapping_key.
    p1 = VECTORS_ROOT / "ecdh_wrap" / "p1-snapshared-r1.json"
    p2 = VECTORS_ROOT / "ecdh_wrap" / "p2-snapshared-r2.json"
    if p1.exists() and p2.exists():
        a = json.loads(p1.read_text("utf-8"))
        b = json.loads(p2.read_text("utf-8"))
        if a["inputs"]["snapshot_id"] != b["inputs"]["snapshot_id"]:
            errors.append("ecdh_wrap: p1/p2 must share snapshot_id")
        if a["expected"]["wrapping_key_hex"] == b["expected"]["wrapping_key_hex"]:
            errors.append("ecdh_wrap: p1/p2 must produce distinct wrapping_key")
        if a["inputs"]["recipient_public_key_uncompressed_hex"] == b["inputs"]["recipient_public_key_uncompressed_hex"]:
            errors.append("ecdh_wrap: p1/p2 must have different recipients")

    # AC #7: hash_chain first entry previous_entry_hash is 32 zero bytes.
    zeros = "00" * 32
    for stem in ("p1-len1", "p2-len2", "p3-len5"):
        f = VECTORS_ROOT / "hash_chain" / f"{stem}.json"
        if not f.exists():
            continue
        b = json.loads(f.read_text("utf-8"))
        first = b["inputs"]["chain"][0]["previous_entry_hash_hex"]
        if first != zeros:
            errors.append(f"hash_chain {stem}: first previous_entry_hash_hex must be 32 zero bytes")

    # Print summary.
    total_pos = sum(c["positive"] for c in counts.values())
    total_neg = sum(c["negative"] for c in counts.values())
    print("Test-vector self-check summary:")
    for d in DIRS:
        c = counts[d]
        print(f"  {d:<16} total={c['total']} positives={c['positive']} negatives={c['negative']}")
    print(f"  TOTAL            positives={total_pos} negatives={total_neg}")
    if errors:
        print("\nSELF-CHECK FAILURES:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("\nAll self-checks passed.")
    return 0


def main() -> int:
    write_all()
    return self_check()


if __name__ == "__main__":
    sys.exit(main())
