"""Deterministic generator for the shared per-primitive test vectors.

Re-emits every bundle under `src/shared/test_vectors/<primitive>/` from the
literal inputs embedded in this module. The generator is the tamper-detection
mechanism for the vectors: any drift in a primitive, a literal, or the bundle
shape surfaces as a CI diff.

Each emitter takes explicit `nonce` / `seed` / `private_key` literals — the
module body never calls `secrets.token_bytes` or `os.urandom`. Negative
fixtures are derived from their sibling positive by a single, mechanical
byte-flip in the named field.

Run from the repo root:

    make vectors           # rewrite vectors (only when bytes differ)
    make vectors-check     # exit non-zero on any drift (CI guard)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pke_backend.crypto.canonicalize import canonicalize
from pke_backend.crypto.encoding import hex_encode
from pke_backend.crypto.hashing import sha256
from pke_backend.crypto.kdf import hkdf_sha256

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS_ROOT = REPO_ROOT / "src" / "shared" / "test_vectors"

# ---------------------------------------------------------------------------
# Constants — protocol labels from context/16_canonical_encoding.md (v0.1)
# ---------------------------------------------------------------------------

HKDF_SALT = b"pke/v0.1/keywrap/salt"
HKDF_INFO_PREFIX = b"pke/v0.1/keywrap/info"
AEAD_AAD_PREFIX = b"pke/v0.1/keywrap/aad"

# P-256 group order (FIPS 186-4 / SEC2 secp256r1).
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------


def _make_bundle(
    *,
    name: str,
    inputs: dict[str, Any],
    expected: dict[str, Any],
    valid: bool,
    notes: str | None = None,
) -> OrderedDict[str, Any]:
    """Build a bundle with the canonical top-level key order."""
    bundle: OrderedDict[str, Any] = OrderedDict()
    bundle["name"] = name
    bundle["inputs"] = inputs
    bundle["expected"] = expected
    bundle["valid"] = valid
    if notes is not None:
        bundle["notes"] = notes
    return bundle


def _bundle_bytes(bundle: dict[str, Any]) -> bytes:
    """Serialize a bundle to the on-disk byte form (UTF-8 + trailing newline).

    Note: ``sort_keys=False``. Bundles are constructed with explicit insertion
    order via :func:`_make_bundle`, and tests pin that order. Sorting top-level
    keys would re-order e.g. ``broken_at_index`` ahead of ``entry_hashes_hex``
    and break byte-for-byte equality (AC 3).
    """
    return (json.dumps(bundle, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _write_bundle(out_path: Path, bundle: dict[str, Any], *, check: bool) -> bool:
    """Write ``bundle`` to ``out_path``. Returns True iff bytes differ from disk.

    In ``check`` mode, never writes — the caller uses the return value to fail
    CI when committed bytes drift from the generator.
    """
    payload = _bundle_bytes(bundle)
    existing = out_path.read_bytes() if out_path.exists() else None
    if existing == payload:
        return False
    if not check:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(payload)
    return True


# ---------------------------------------------------------------------------
# Byte-flip helpers — used to derive every negative fixture from its positive
# ---------------------------------------------------------------------------


def _flip_byte_hex(hex_str: str, offset: int, mask: int = 0x01) -> str:
    """Return ``hex_str`` with the byte at ``offset`` XORed against ``mask``."""
    raw = bytearray.fromhex(hex_str)
    raw[offset] ^= mask
    return raw.hex()


# ---------------------------------------------------------------------------
# Deterministic ECDSA-P256-SHA256 + low-s normalization
#
# Note: the nonce ``k`` is derived from a SHA-256-keyed hash of
# (label || sk || h || counter) rather than RFC 6979. This matches the scheme
# used to author the committed vectors (HLAM-15); changing it would break AC 3
# byte-for-byte equivalence. The signatures still verify under any standard
# ECDSA-P256-SHA256 verifier because the scheme only fixes ``k`` deterministically.
# ---------------------------------------------------------------------------

_ECDSA_K_LABEL = b"pke/v0.1/test-vectors/k/"


def _derive_k(secret: int, msg_hash: bytes, counter: int) -> int:
    material = hashlib.sha256(
        _ECDSA_K_LABEL + secret.to_bytes(32, "big") + msg_hash + counter.to_bytes(4, "big"),
    ).digest()
    return (int.from_bytes(material, "big") % (_P256_N - 1)) + 1


def _p1363_sign(private_key_pem: str, message: bytes) -> bytes:
    """Sign ``message`` with ECDSA-P256-SHA256 + low-s, return raw 64-byte P1363."""
    key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise TypeError("expected a P-256 EllipticCurvePrivateKey")
    secret = key.private_numbers().private_value
    msg_hash = hashlib.sha256(message).digest()
    h_int = int.from_bytes(msg_hash, "big")

    counter = 0
    while True:
        k = _derive_k(secret, msg_hash, counter)
        r = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers().x % _P256_N
        if r == 0:
            counter += 1
            continue
        s = (pow(k, -1, _P256_N) * (h_int + r * secret)) % _P256_N
        if s == 0:
            counter += 1
            continue
        if s > _P256_N // 2:
            s = _P256_N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# ECDH + HKDF + AES-GCM key wrap composer (HLAM-3 §HKDF-SHA256)
# ---------------------------------------------------------------------------


def _ecdh_shared_secret(sender_pem: str, recipient_pub_uncompressed: bytes) -> bytes:
    sender_key = serialization.load_pem_private_key(sender_pem.encode("ascii"), password=None)
    if not isinstance(sender_key, ec.EllipticCurvePrivateKey):
        raise TypeError("expected sender EllipticCurvePrivateKey")
    recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), recipient_pub_uncompressed)
    return sender_key.exchange(ec.ECDH(), recipient_pub)


def _hkdf_info_for_wrap(snapshot_id: str, recipient_pub_uncompressed: bytes) -> bytes:
    sid = snapshot_id.encode("utf-8")
    return (
        HKDF_INFO_PREFIX
        + len(sid).to_bytes(2, "big")
        + sid
        + len(recipient_pub_uncompressed).to_bytes(2, "big")
        + recipient_pub_uncompressed
    )


def _aead_aad_for_wrap(snapshot_id: str) -> bytes:
    sid = snapshot_id.encode("utf-8")
    return AEAD_AAD_PREFIX + len(sid).to_bytes(2, "big") + sid


# ---------------------------------------------------------------------------
# Hash-chain helpers
# ---------------------------------------------------------------------------


def _compute_entry_hashes(chain: Sequence[Mapping[str, Any]]) -> list[str]:
    """Compute ``entry_hash`` (hex) for each entry as SHA256(canonical_json(entry))."""
    return [hex_encode(sha256(canonicalize(dict(entry)))) for entry in chain]


# ---------------------------------------------------------------------------
# Emitters — one per primitive directory
# ---------------------------------------------------------------------------


def emit_canonical_json(out_dir: Path, *, check: bool) -> list[Path]:
    """4 positives via :func:`canonicalize` + 1 bespoke negative (duplicate key)."""
    cases: list[tuple[str, dict[str, Any], str | None]] = [
        ("p1-empty-object", {}, None),
        # Insertion order is deliberately scrambled here; canonicalize() sorts.
        (
            "p2-flat-mixed",
            OrderedDict([("b", 2), ("a", "x"), ("c", True)]),
            "Keys must sort lexicographically: a, b, c.",
        ),
        (
            "p3-nested-arrays",
            OrderedDict(
                [
                    (
                        "outer",
                        OrderedDict(
                            [
                                ("y", [1, 2, OrderedDict([("z", "deep"), ("a", None)])]),
                                ("x", False),
                            ],
                        ),
                    ),
                    ("alpha", "first"),
                ],
            ),
            "Nested key ordering applies recursively; array order is preserved.",
        ),
        (
            "p4-unicode",
            OrderedDict([("name", "café"), ("city", "São Paulo"), ("symbol", "→")]),
            "ensure_ascii=False — non-ASCII characters are emitted as raw UTF-8 bytes.",
        ),
    ]

    written: list[Path] = []
    for name, value, notes in cases:
        canonical = canonicalize(value)
        bundle = _make_bundle(
            name=name,
            inputs=OrderedDict([("value", value)]),
            expected=OrderedDict([("canonical_bytes_hex", hex_encode(canonical))]),
            valid=True,
            notes=notes,
        )
        path = out_dir / f"{name}.json"
        if _write_bundle(path, bundle, check=check):
            written.append(path)

    # Bespoke negative: raw UTF-8 bytes of a duplicate-key document.
    n1 = _make_bundle(
        name="n1-duplicate-key",
        inputs=OrderedDict([("raw_utf8_hex", hex_encode(b'{"a":1,"a":2}'))]),
        expected=OrderedDict([("error", "duplicate_key")]),
        valid=False,
        notes=(
            "Decoder MUST reject documents with duplicate keys at the same level. "
            "Per HLAM-3 canonical-JSON rules, duplicate keys are invalid on decode."
        ),
    )
    path = out_dir / "n1-duplicate-key.json"
    if _write_bundle(path, n1, check=check):
        written.append(path)

    return written


def emit_sha256(out_dir: Path, *, check: bool) -> list[Path]:
    long_msg_hex = (
        "db45c222e4b6aae6e328842df6ce6a3a5413905dcb4148a6b0a842c822012a78"
        "3f172b834480cb3c8ceb9374d26e21ae55cef8f43dadb03d0d033d6601faccca"
        "6cd3c9d3ae4379e7fc42d579d9e1d02dc690f6797468eacf8c19147048b28f08"
        "22e738b9d9118c773e5cbcb6d7e83b04f84b8bdcdabafe872277e439251a60be"
        "94d9d6e64fcd831a635b36b78ec6fea700a52a2c90e814a999c6e4d273ec9352"
        "090d8c7a89c658a6fb3d445dc815a63b8de21ace0e3aa35b29eecb8da74ee249"
        "7d0693d050eb093085ac005e0488eb85e401fe3b1ef619b804214724b15349b3"
        "2446803300be8f27e58de54a32f658378cd88002507733dfd5be8960c79f26ca"
    )
    positives: list[tuple[str, str]] = [
        ("p1-empty", ""),
        ("p2-short-abc", "616263"),
        ("p3-longer-synthetic", long_msg_hex),
    ]

    written: list[Path] = []
    p2_digest_hex: str | None = None
    for name, msg_hex in positives:
        digest = sha256(bytes.fromhex(msg_hex))
        digest_hex = hex_encode(digest)
        if name == "p2-short-abc":
            p2_digest_hex = digest_hex
        bundle = _make_bundle(
            name=name,
            inputs=OrderedDict([("message_hex", msg_hex)]),
            expected=OrderedDict([("digest_hex", digest_hex)]),
            valid=True,
        )
        path = out_dir / f"{name}.json"
        if _write_bundle(path, bundle, check=check):
            written.append(path)

    assert p2_digest_hex is not None
    n1 = _make_bundle(
        name="n1-mutated-digest",
        inputs=OrderedDict([("message_hex", "616263")]),
        expected=OrderedDict([("digest_hex", _flip_byte_hex(p2_digest_hex, offset=7))]),
        valid=False,
        notes=(
            "Sibling positive: p2-short-abc. expected.digest_hex byte at offset 7 "
            "flipped (XOR 0x01); implementation hashing inputs.message_hex will NOT "
            "match."
        ),
    )
    path = out_dir / "n1-mutated-digest.json"
    if _write_bundle(path, n1, check=check):
        written.append(path)

    return written


# PEM literals are embedded verbatim — replacing them invalidates committed
# signatures (AC 3). Do not regenerate without intent.
_ECDSA_PEM_P1 = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgA0k7MWRWbGLPaKyv\n"
    "1lVDCRZfacNpn1QIbdce5GxEJAKhRANCAATLyA66CTEJE6JO7FH1+QD312GEupK9\n"
    "tUaVMtSpN20Yje554EeG+lqi+fFbuR0EMMjJuFp4+9Ul9TamUfpKeUHS\n"
    "-----END PRIVATE KEY-----\n"
)
_ECDSA_PUB_P1_HEX = (
    "04cbc80eba09310913a24eec51f5f900f7d76184ba92bdb5469532d4a9376d188d"
    "ee79e04786fa5aa2f9f15bb91d0430c8c9b85a78fbd525f536a651fa4a7941d2"
)
_ECDSA_PEM_P2 = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXJHt6cIxTXRaw7B2\n"
    "htvX8YG1Trtrmmp76f1YjU05Mx6hRANCAAQu9A4J11R0FGCO9MauMYLOM+X6k7xe\n"
    "SRRrvvcF0A6QdfquyzqR8KQqDXXHJRtiuLwTEDKYhlQdHvKTsw4I3RsX\n"
    "-----END PRIVATE KEY-----\n"
)
_ECDSA_PUB_P2_HEX = (
    "042ef40e09d7547414608ef4c6ae3182ce33e5fa93bc5e49146bbef705d00e9075"
    "faaecb3a91f0a42a0d75c7251b62b8bc1310329886541d1ef293b30e08dd1b17"
)
_ECDSA_PEM_P3 = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZoH/ikosFIxleTld\n"
    "svUoMUJU6D9XlVKtGXGTXqs0iv2hRANCAAQ521sUOfIBk6T5he0OFMjpyb07rm5L\n"
    "3EHtSr0rXklg59xEvYUQ2jWpolNhmN7+IoG96L5EmVHLwCM798Ma01l0\n"
    "-----END PRIVATE KEY-----\n"
)
_ECDSA_PUB_P3_HEX = (
    "0439db5b1439f20193a4f985ed0e14c8e9c9bd3bae6e4bdc41ed4abd2b5e4960e7"
    "dc44bd8510da35a9a2536198defe2281bde8be449951cbc0233bf7c31ad35974"
)
_ECDSA_DETERMINISTIC_NOTES = "Deterministic ECDSA with low-s normalization for byte-stable test vectors."


def emit_ecdsa_p256(out_dir: Path, *, check: bool) -> list[Path]:
    cases: list[tuple[str, str, str, str]] = [
        # name, PEM, pub_hex, message_hex
        (
            "p1-snapshot-commit",
            _ECDSA_PEM_P1,
            _ECDSA_PUB_P1_HEX,
            "7b226b696e64223a22736e617073686f74222c22736571223a317d",
        ),
        (
            "p2-attestation",
            _ECDSA_PEM_P2,
            _ECDSA_PUB_P2_HEX,
            "7b226b696e64223a226174746573746174696f6e222c22736571223a34322c2268617368223a22616263227d",
        ),
        (
            "p3-binary-payload",
            _ECDSA_PEM_P3,
            _ECDSA_PUB_P3_HEX,
            (
                "843b96517bcc938b2d3319685e0a544c6ed7aab8baf21b0e242b1786e8b333f2"
                "7f681eea3dde58b284216ed0f0728a1a76cf799959690ff5e377625080e73c11"
                "6086ddc121e7c7005bcfb92ae57418feb9a1814b261340f6297ce3deb24226f2"
                "318e58e4d026ec8b5135bcf632fbfd9e13201aa5a07413450ed150388069823b"
            ),
        ),
    ]

    written: list[Path] = []
    p1_signature_hex: str | None = None
    for name, pem, pub_hex, msg_hex in cases:
        signature = _p1363_sign(pem, bytes.fromhex(msg_hex))
        signature_hex = hex_encode(signature)
        if name == "p1-snapshot-commit":
            p1_signature_hex = signature_hex
        bundle = _make_bundle(
            name=name,
            inputs=OrderedDict(
                [
                    ("private_key_pkcs8_pem", pem),
                    ("public_key_uncompressed_hex", pub_hex),
                    ("message_hex", msg_hex),
                ],
            ),
            expected=OrderedDict([("signature_p1363_hex", signature_hex)]),
            valid=True,
            notes=_ECDSA_DETERMINISTIC_NOTES,
        )
        path = out_dir / f"{name}.json"
        if _write_bundle(path, bundle, check=check):
            written.append(path)

    assert p1_signature_hex is not None
    n1 = _make_bundle(
        name="n1-flipped-signature",
        inputs=OrderedDict(
            [
                ("private_key_pkcs8_pem", _ECDSA_PEM_P1),
                ("public_key_uncompressed_hex", _ECDSA_PUB_P1_HEX),
                ("message_hex", "7b226b696e64223a22736e617073686f74222c22736571223a317d"),
            ],
        ),
        expected=OrderedDict([("signature_p1363_hex", _flip_byte_hex(p1_signature_hex, offset=33))]),
        valid=False,
        notes=(
            "Sibling positive: p1-snapshot-commit. expected.signature_p1363_hex byte "
            "at offset 33 flipped (XOR 0x01); verification MUST fail."
        ),
    )
    path = out_dir / "n1-flipped-signature.json"
    if _write_bundle(path, n1, check=check):
        written.append(path)

    return written


def emit_hkdf_sha256(out_dir: Path, *, check: bool) -> list[Path]:
    ikm_hex = "c660c9a5371557cd2bfa36a96b95e756f7c86ce35511f9d48509848b4419ff4a"
    recipient_a_hex = (
        "046420391c846f0e2472fecaf7b573d7538d29941d31895217d09a3367c9e11c61"
        "04648894b39e3087346ab054f5627535b5077defc91285784d287c60f793ee55"
    )
    recipient_b_hex = (
        "04264cbb7e0304c3a69e90f4e0da0884f9b9e3fdeba9fe3cd2470a1efb37e783e5"
        "81140423e6d797676356bf0181f5fa8ef276da7e2bba08f3d04ae1c910bbcd9a"
    )
    cases: list[tuple[str, str, str]] = [
        ("p1-snap0001-r1", "snap-0001", recipient_a_hex),
        ("p2-snap0001-r2", "snap-0001", recipient_b_hex),
        ("p3-snap0002-r1", "snap-0002", recipient_a_hex),
    ]
    notes_text = (
        "HKDF-SHA256 with salt=b'pke/v0.1/keywrap/salt' and length-prefixed info per HLAM-3 canonical-encoding spec."
    )

    written: list[Path] = []
    p1_info_hex: str | None = None
    for name, snapshot_id, recipient_hex in cases:
        info = _hkdf_info_for_wrap(snapshot_id, bytes.fromhex(recipient_hex))
        okm = hkdf_sha256(bytes.fromhex(ikm_hex), HKDF_SALT, info, 32)
        info_hex = hex_encode(info)
        if name == "p1-snap0001-r1":
            p1_info_hex = info_hex
        bundle = _make_bundle(
            name=name,
            inputs=OrderedDict(
                [
                    ("ikm_hex", ikm_hex),
                    ("snapshot_id", snapshot_id),
                    ("recipient_public_key_hex", recipient_hex),
                ],
            ),
            expected=OrderedDict(
                [
                    ("salt_hex", hex_encode(HKDF_SALT)),
                    ("info_hex", info_hex),
                    ("okm_hex", hex_encode(okm)),
                ],
            ),
            valid=True,
            notes=notes_text,
        )
        path = out_dir / f"{name}.json"
        if _write_bundle(path, bundle, check=check):
            written.append(path)

    assert p1_info_hex is not None
    # Negative is a *metadata* mutation: same inputs as p1, expected.info_hex
    # corrupted at offset 5 (XOR 0x01) but okm_hex unchanged. An implementation
    # rederiving from inputs will produce okm_hex correctly yet its computed
    # info bytes will not match the corrupted expected.info_hex.
    p1_info_hex_str = p1_info_hex
    n1_okm_hex = hex_encode(
        hkdf_sha256(
            bytes.fromhex(ikm_hex),
            HKDF_SALT,
            _hkdf_info_for_wrap("snap-0001", bytes.fromhex(recipient_a_hex)),
            32,
        ),
    )
    n1 = _make_bundle(
        name="n1-wrong-info-bytes",
        inputs=OrderedDict(
            [
                ("ikm_hex", ikm_hex),
                ("snapshot_id", "snap-0001"),
                ("recipient_public_key_hex", recipient_a_hex),
            ],
        ),
        expected=OrderedDict(
            [
                ("salt_hex", hex_encode(HKDF_SALT)),
                ("info_hex", _flip_byte_hex(p1_info_hex_str, offset=5)),
                ("okm_hex", n1_okm_hex),
            ],
        ),
        valid=False,
        notes=(
            "Sibling positive: p1-snap0001-r1. expected.info_hex byte at offset 5 "
            "flipped (XOR 0x01) while expected.okm_hex retains the correct value. "
            "An implementation that ingests inputs and constructs info per the "
            "HLAM-3 spec will produce expected.okm_hex but its computed info_hex "
            "will NOT match the (deliberately corrupted) expected.info_hex — "
            "surfacing the mismatch."
        ),
    )
    path = out_dir / "n1-wrong-info-bytes.json"
    if _write_bundle(path, n1, check=check):
        written.append(path)

    return written


def emit_aes_gcm(out_dir: Path, *, check: bool) -> list[Path]:
    _aes_gcm_nonce_notes = "Nonce is fixed for determinism; production code MUST use a random nonce."

    cases: list[tuple[str, str, str, str, str, str | None]] = [
        # name, key_hex, nonce_hex, aad_hex, plaintext_hex, notes (None => use default)
        (
            "p1-empty-aad",
            "12fc56b44c07d7b852d511e87fdf06a8a79d32ed36d0b61c093706043f560ce2",
            "155971fc971298c159b907cc",
            "",
            "68656c6c6f20776f726c64",
            None,
        ),
        (
            "p2-real-aad",
            "61e6f47c87123fbfca7383852a7703f4bd7b1ef6b1ba24bafa43d2db703d559e",
            "e3e4c868ac4ff4e1c21d4ffb",
            "706b652f76302e312f6b6579777261702f6161640009736e61702d58595a41",
            "cf3218514993d2e647f66c4a2965dded3b906fea9c8c60b1a8b07037233c9032",
            None,
        ),
        (
            "p3-larger-plaintext",
            "123e45f64e7a58585b81f04aa199bac6dc98137e0ea31ba3763df2bc96ba85af",
            "affc3231d3aa21231fc9d369",
            "636f6e746578742f7631",
            _LARGE_PLAINTEXT_HEX,
            None,
        ),
    ]

    written: list[Path] = []
    p2_tag_hex: str | None = None
    for name, key_hex, nonce_hex, aad_hex, plaintext_hex, custom_notes in cases:
        key = bytes.fromhex(key_hex)
        nonce = bytes.fromhex(nonce_hex)
        aad = bytes.fromhex(aad_hex)
        plaintext = bytes.fromhex(plaintext_hex)
        ct_with_tag = AESGCM(key).encrypt(nonce, plaintext, aad or None)
        ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]
        tag_hex = hex_encode(tag)
        if name == "p2-real-aad":
            p2_tag_hex = tag_hex
        bundle = _make_bundle(
            name=name,
            inputs=OrderedDict(
                [
                    ("key_hex", key_hex),
                    ("nonce_hex", nonce_hex),
                    ("aad_hex", aad_hex),
                    ("plaintext_hex", plaintext_hex),
                ],
            ),
            expected=OrderedDict(
                [
                    ("ciphertext_hex", hex_encode(ciphertext)),
                    ("tag_hex", tag_hex),
                ],
            ),
            valid=True,
            notes=custom_notes or _aes_gcm_nonce_notes,
        )
        path = out_dir / f"{name}.json"
        if _write_bundle(path, bundle, check=check):
            written.append(path)

    assert p2_tag_hex is not None
    # Negative: same inputs as p2; ciphertext intact; tag byte at offset 4 flipped.
    p2 = cases[1]
    key = bytes.fromhex(p2[1])
    nonce = bytes.fromhex(p2[2])
    aad = bytes.fromhex(p2[3])
    plaintext = bytes.fromhex(p2[4])
    ct_with_tag = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    p2_ciphertext_hex = hex_encode(ct_with_tag[:-16])
    n1 = _make_bundle(
        name="n1-corrupted-tag",
        inputs=OrderedDict(
            [
                ("key_hex", p2[1]),
                ("nonce_hex", p2[2]),
                ("aad_hex", p2[3]),
                ("plaintext_hex", p2[4]),
            ],
        ),
        expected=OrderedDict(
            [
                ("ciphertext_hex", p2_ciphertext_hex),
                ("tag_hex", _flip_byte_hex(p2_tag_hex, offset=4)),
            ],
        ),
        valid=False,
        notes=(
            "Sibling positive: p2-real-aad. expected.tag_hex byte at offset 4 "
            "flipped (XOR 0x01); AES-GCM tag verification MUST fail on decrypt."
        ),
    )
    path = out_dir / "n1-corrupted-tag.json"
    if _write_bundle(path, n1, check=check):
        written.append(path)

    return written


_ECDH_WRAP_NOTES = (
    "End-to-end ecdhp256+aesgcm256 wrap. AEAD nonce is fixed for determinism; "
    "production code MUST use a random 12-byte nonce per encryption."
)

_ECDH_SENDER_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3RQ/CInQPQaF+67M\n"
    "gyzT5+9cZc437Fnm1zBVKSmdn4ehRANCAAR2RozgO1oViCb5V/J/qL8HQO5eox4/\n"
    "ovOTvD7NTq4UE32VaVhqArdVcck56+N9DoM7xFlchHdzBGbJ/uU2gARz\n"
    "-----END PRIVATE KEY-----\n"
)
_ECDH_SENDER_PUB_HEX = (
    "0476468ce03b5a158826f957f27fa8bf0740ee5ea31e3fa2f393bc3ecd4eae1413"
    "7d9569586a02b75571c939ebe37d0e833bc4595c8477730466c9fee536800473"
)
_ECDH_RECIPIENT_A_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzgheoFGGVj9vTUZ8\n"
    "45NnWS7Kb6X/dwT7lq0P/+zOPnKhRANCAARkIDkchG8OJHL+yve1c9dTjSmUHTGJ\n"
    "UhfQmjNnyeEcYQRkiJSznjCHNGqwVPVidTW1B33vyRKFeE0ofGD3k+5V\n"
    "-----END PRIVATE KEY-----\n"
)
_ECDH_RECIPIENT_A_PUB_HEX = (
    "046420391c846f0e2472fecaf7b573d7538d29941d31895217d09a3367c9e11c61"
    "04648894b39e3087346ab054f5627535b5077defc91285784d287c60f793ee55"
)
_ECDH_RECIPIENT_B_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgo3nykLvhx0lbFYg9\n"
    "KfbnPZTf4PshlRFixyZlqHCIAeChRANCAAQmTLt+AwTDpp6Q9ODaCIT5ueP966n+\n"
    "PNJHCh77N+eD5YEUBCPm15dnY1a/AYH1+o7ydtp+K7oI89BK4ckQu82a\n"
    "-----END PRIVATE KEY-----\n"
)
_ECDH_RECIPIENT_B_PUB_HEX = (
    "04264cbb7e0304c3a69e90f4e0da0884f9b9e3fdeba9fe3cd2470a1efb37e783e5"
    "81140423e6d797676356bf0181f5fa8ef276da7e2bba08f3d04ae1c910bbcd9a"
)
_ECDH_SNAPSHOT_ID = "snap-shared"
_ECDH_SNAPSHOT_KEY_HEX = "30eae0ec5230625ca21afa98cdbcea8ff1865ffdc178a201dcb87e5e956b20b1"
_ECDH_AEAD_NONCE_HEX = "a264ff0a8ed7762ccba985dd"


def _build_ecdh_wrap_bundle(
    name: str,
    recipient_pem: str,
    recipient_pub_hex: str,
    *,
    valid: bool,
    expected_overrides: dict[str, str] | None = None,
    notes: str | None,
) -> tuple[OrderedDict[str, Any], dict[str, str]]:
    """Compose one ECDH-wrap bundle and return (bundle, computed_expected_hex)."""
    snapshot_key = bytes.fromhex(_ECDH_SNAPSHOT_KEY_HEX)
    recipient_pub = bytes.fromhex(recipient_pub_hex)
    nonce = bytes.fromhex(_ECDH_AEAD_NONCE_HEX)

    shared = _ecdh_shared_secret(_ECDH_SENDER_PEM, recipient_pub)
    info = _hkdf_info_for_wrap(_ECDH_SNAPSHOT_ID, recipient_pub)
    aad = _aead_aad_for_wrap(_ECDH_SNAPSHOT_ID)
    wrapping_key = hkdf_sha256(shared, HKDF_SALT, info, 32)
    ct_with_tag = AESGCM(wrapping_key).encrypt(nonce, snapshot_key, aad)
    wrapped = nonce + ct_with_tag

    computed = OrderedDict(
        [
            ("shared_secret_hex", hex_encode(shared)),
            ("hkdf_info_hex", hex_encode(info)),
            ("hkdf_aad_hex", hex_encode(aad)),
            ("wrapping_key_hex", hex_encode(wrapping_key)),
            ("wrapped_key_hex", hex_encode(wrapped)),
        ],
    )

    expected: OrderedDict[str, str] = OrderedDict(computed)
    if expected_overrides:
        for key, value in expected_overrides.items():
            expected[key] = value

    bundle = _make_bundle(
        name=name,
        inputs=OrderedDict(
            [
                ("snapshot_id", _ECDH_SNAPSHOT_ID),
                ("snapshot_key_hex", _ECDH_SNAPSHOT_KEY_HEX),
                ("sender_private_key_pkcs8_pem", _ECDH_SENDER_PEM),
                ("sender_public_key_uncompressed_hex", _ECDH_SENDER_PUB_HEX),
                ("recipient_private_key_pkcs8_pem", recipient_pem),
                ("recipient_public_key_uncompressed_hex", recipient_pub_hex),
                ("aead_nonce_hex", _ECDH_AEAD_NONCE_HEX),
            ],
        ),
        expected=expected,
        valid=valid,
        notes=notes,
    )
    return bundle, dict(computed)


def emit_ecdh_wrap(out_dir: Path, *, check: bool) -> list[Path]:
    written: list[Path] = []
    p1, p1_computed = _build_ecdh_wrap_bundle(
        "p1-snapshared-r1",
        _ECDH_RECIPIENT_A_PEM,
        _ECDH_RECIPIENT_A_PUB_HEX,
        valid=True,
        notes=_ECDH_WRAP_NOTES,
    )
    path = out_dir / "p1-snapshared-r1.json"
    if _write_bundle(path, p1, check=check):
        written.append(path)

    p2, _ = _build_ecdh_wrap_bundle(
        "p2-snapshared-r2",
        _ECDH_RECIPIENT_B_PEM,
        _ECDH_RECIPIENT_B_PUB_HEX,
        valid=True,
        notes=_ECDH_WRAP_NOTES,
    )
    path = out_dir / "p2-snapshared-r2.json"
    if _write_bundle(path, p2, check=check):
        written.append(path)

    # Negative: flip one byte in p1.expected.wrapped_key_hex@30.
    n1, _ = _build_ecdh_wrap_bundle(
        "n1-corrupted-wrapped-key",
        _ECDH_RECIPIENT_A_PEM,
        _ECDH_RECIPIENT_A_PUB_HEX,
        valid=False,
        expected_overrides={
            "wrapped_key_hex": _flip_byte_hex(p1_computed["wrapped_key_hex"], offset=30),
        },
        notes=(
            "Sibling positive: p1-snapshared-r1. expected.wrapped_key_hex byte at "
            "offset 30 flipped (XOR 0x01); AEAD tag verification MUST fail on unwrap."
        ),
    )
    path = out_dir / "n1-corrupted-wrapped-key.json"
    if _write_bundle(path, n1, check=check):
        written.append(path)

    return written


def emit_hash_chain(out_dir: Path, *, check: bool) -> list[Path]:
    notes_text = (
        "entry_hash[i] = SHA256(canonical_json(entry_i)); entry_i includes "
        "previous_entry_hash_hex which is entry_hash[i-1] (or 32 zero bytes for "
        "genesis)."
    )
    genesis_prev = "0" * 64

    # Per-entry payload hashes are literal seeds — drift here invalidates AC 3.
    p1_payload = "86bce9d25a4884c67d1deaea258b52c8037f7b526f9eefb917eba2e5dfd5d624"
    p2_payloads = [
        "3836d2ab015fb2de3588e46a26d792e2c504778b314a0fca848aeb34633000ff",
        "d168bf4e48ab40119218e051a758060620f7eac8b2d0d663447bf866cb7df703",
    ]
    p3_payloads = [
        "fb17bbe2a8cbda1d0b262ecd34da07065a4830d9224b81680ab8aa600d7731e9",
        "98f5d5c5d4dd7dda926792db370710d2bc1f7c70d3399d802817444ea3d92dfa",
        "2fcc80db2509fb9c32e7ec3e3ef93e3ccdb4641d3811467ed60add5766fa6402",
        "0855b620462270ea348141026a0c2f58efb5d91fb229765ebdc0ab1e4c2bb605",
        "ef2acd9aa3f0c771dbaf5fa41bdfa6ea284abc3e879c73d81bb49b8a318a5b13",
    ]

    def _build_chain(payloads: list[str]) -> list[OrderedDict[str, Any]]:
        chain: list[OrderedDict[str, Any]] = []
        prev_hash = genesis_prev
        for seq, payload_hex in enumerate(payloads):
            entry: OrderedDict[str, Any] = OrderedDict(
                [
                    ("seq", seq),
                    ("payload_hash_hex", payload_hex),
                    ("previous_entry_hash_hex", prev_hash),
                ],
            )
            prev_hash = hex_encode(sha256(canonicalize(entry)))
            chain.append(entry)
        return chain

    written: list[Path] = []

    for name, payloads in [
        ("p1-len1", [p1_payload]),
        ("p2-len2", p2_payloads),
        ("p3-len5", p3_payloads),
    ]:
        chain = _build_chain(payloads)
        bundle = _make_bundle(
            name=name,
            inputs=OrderedDict([("chain", chain)]),
            expected=OrderedDict([("entry_hashes_hex", _compute_entry_hashes(chain))]),
            valid=True,
            notes=notes_text,
        )
        path = out_dir / f"{name}.json"
        if _write_bundle(path, bundle, check=check):
            written.append(path)

    # Negative: mutate p3.inputs.chain[2].payload_hash_hex@11 BUT keep the
    # original (pre-mutation) entry_hashes_hex — an implementation recomputing
    # the chain over the mutated input will diverge at broken_at_index=2.
    original_chain = _build_chain(p3_payloads)
    original_entry_hashes = _compute_entry_hashes(original_chain)
    mutated_chain: list[OrderedDict[str, Any]] = []
    for idx, entry in enumerate(original_chain):
        new_entry = OrderedDict(entry)
        if idx == 2:
            new_entry["payload_hash_hex"] = _flip_byte_hex(entry["payload_hash_hex"], offset=11)
        mutated_chain.append(new_entry)

    n1 = _make_bundle(
        name="n1-mutated-middle-link",
        inputs=OrderedDict([("chain", mutated_chain)]),
        expected=OrderedDict(
            [
                ("entry_hashes_hex", original_entry_hashes),
                ("broken_at_index", 2),
            ],
        ),
        valid=False,
        notes=(
            "Sibling positive: p3-len5. inputs.chain[2].payload_hash_hex byte at "
            "offset 11 flipped (XOR 0x01). expected.entry_hashes_hex retains the "
            "original chain's hashes; an implementation recomputing entry_hash "
            "over the mutated chain will diverge starting at index 2 "
            "(broken_at_index)."
        ),
    )
    path = out_dir / "n1-mutated-middle-link.json"
    if _write_bundle(path, n1, check=check):
        written.append(path)

    return written


# Larger plaintext for aes_gcm/p3 — pulled out so the cases table stays readable.
_LARGE_PLAINTEXT_HEX = (
    "8531ed6695f30f7f7b88795e4afb6604eb09dd8bfcf487c5991be24112c953a8"
    "defcb9e58ba66be1197b744fa9053c688f949ca3391f937c991a37523d7444ca"
    "dc5d99dfad83bd2a1c8714f21c96ea070a1957832b5c11e2f3730145d8ec19e7"
    "e768d2bcb2c9e5504adb457e14b66948bf3c9755b83a65a3fedec1ef5ed501c2"
    "9e0e6efb1b0c8969e475f2f57247ded41c79ddba2d4ba5bdfe547fd65a72db98"
    "4b51e493938701ad658b09e2945acd5d6c1a3dd43335e76ae313ab84479144a7"
    "50fb3d13b22aa24c3525765efbbf9650a7dd308a98aeee695baf012fd853f8a7"
    "5a88c52739aff2d62ccf58f97d90d502a70476ccddb29393f4038e908323325a"
    "48a57e7dfeb7603468bf00e41d61de91a8056d600d753c29c52c44494f600fe6"
    "f539ee8b5f3467e64bb807bcb419ab3ac48eeec432fcc566bbf23401f7ae0877"
    "782b90d307d9432999d407df6bdea61e184704297e5b1fc7f54bf31e97d09ffb"
    "ea4247bab74dd1411e1c0603ce61d0bdc848486bb7e7e438e42ad974b7a7393a"
    "620a8288393bc50e1a6a413a97db9a7eabf96b832be347bd90fe4520af5e9b78"
    "7f2c9ed266dbdb8da35079273588ecbaa9e323e33d9dc34216ca84495e7eedd1"
    "0367e053a6ee52b3f0cc8fee140437d159512f33eb378d05550ef98b156868fd"
    "29824ff366a77b7ee48cb9520d564a481aa0410eb9ac45df58b168f6ad9a07e6"
    "693a3fad85ac3847a7c7360250b1fb46de9d220a80b30bc69f1ef185445c1220"
    "4f22f46921b55161b3863a11d99e4207efde60533ea08181838a40dd9ab0b637"
    "ceace832a88b1d4165add8cfc4c346e8afebce77355187862a8cc5617e0e0889"
    "4c230292fa79787594621fb71aa7e0d681782eabd83616e57af90e12833236a6"
    "bea46ca5f205ad298f7660b2b5449f1ea178ec0857427e6cf6161ad4cee8c4c0"
    "bd3712736c17434406f99fd7c9ec69b215397a2228667d2d29c0784c88261972"
    "d35292a001e74bbdb5e4a550b4a8d36e9256a18db6c45de08c4666d1c09c25c1"
    "5edaa3de3bc0674bea3f63bf242de8f6d6765037f0bbd1be72ce55bd40613f67"
    "0991718802d90b43651fe5e62319869563476a7c4fd198ff966f6f727e7dbffa"
    "55cb7564bfa421b04eeb7fc79df09fdd546e09bf3c2ef362d953ea0305cb1c7b"
    "5bcaee6d9837b0881e7ad0116d7304a0cad029195aa47995e84847e06c2fa8f2"
    "3936565145c05b92d13354edb5cd2df88891f0323f7b6ec9e5a24673b5559887"
    "1828b7e130504c976af3212c796f532d253ba608e3ebf2b1e9ebbe9e7c18cb0c"
    "885f5241f8d01febb50b22517692a3fc782ab98ad9279239d7c533e3c5542ed2"
    "ac305b890f102495f5fd920aa4755d36242b33483567352a5a268d78af0748da"
    "ab77346aea79aee5315c20fe94833e8361217fe6a71349758fe6214821907b65"
)


# ---------------------------------------------------------------------------
# Dispatch table + entry point
# ---------------------------------------------------------------------------


EMITTERS: dict[str, Callable[[Path, bool], list[Path]]] = OrderedDict(
    [
        ("canonical_json", lambda d, c: emit_canonical_json(d, check=c)),
        ("sha256", lambda d, c: emit_sha256(d, check=c)),
        ("ecdsa_p256", lambda d, c: emit_ecdsa_p256(d, check=c)),
        ("hkdf_sha256", lambda d, c: emit_hkdf_sha256(d, check=c)),
        ("aes_gcm", lambda d, c: emit_aes_gcm(d, check=c)),
        ("ecdh_wrap", lambda d, c: emit_ecdh_wrap(d, check=c)),
        ("hash_chain", lambda d, c: emit_hash_chain(d, check=c)),
    ],
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Regenerate shared per-primitive test vectors.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit non-zero if any committed bundle differs.",
    )
    parser.add_argument(
        "--only",
        choices=sorted(EMITTERS.keys()),
        action="append",
        help="Regenerate only the given primitive directory (repeatable).",
    )
    args = parser.parse_args(argv)

    selected = args.only or list(EMITTERS.keys())
    drifted: list[Path] = []
    for primitive in selected:
        out_dir = VECTORS_ROOT / primitive
        emitter = EMITTERS[primitive]
        changed = emitter(out_dir, args.check)
        drifted.extend(changed)

    if args.check:
        if drifted:
            print(f"DRIFT: {len(drifted)} vector(s) would be rewritten:")
            for path in drifted:
                print(f"  {path.relative_to(REPO_ROOT)}")
            return 1
        print(f"OK: {len(selected)} primitive(s) match committed bundles.")
        return 0

    if drifted:
        print(f"Wrote {len(drifted)} vector(s):")
        for path in drifted:
            print(f"  {path.relative_to(REPO_ROOT)}")
    else:
        print(f"No changes — {len(selected)} primitive(s) already up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
