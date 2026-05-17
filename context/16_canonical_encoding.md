# Canonical Encoding (v0.1)

## Purpose

This document is the single authoritative source for the bytewise encoding of every signed, hashed, and wrapped field in the PKE protocol.

It exists so that two independent implementations — Swift (`swift-crypto` / CryptoKit) on iOS and Python (`cryptography`) on the backend — can produce **byte-identical output** and verify each other's vectors.

The rules below are **locked at v0.1**. Changing any of them silently invalidates every signature, attestation, ledger entry, and key grant produced under v0.1. Future changes mint a new version identifier rather than mutating these values in place (see [Versioning](#versioning)).

This spec is normative for the five JSON Schemas in `src/shared/schemas/`:

- `snapshot_commitment.json`
- `witness_attestation.json`
- `ledger_entry.json`
- `key_grant.json`
- `verification_report.json`

The schemas define **which fields exist**. This document defines **how their bytes are produced**.

## Scope

This spec covers:

- Canonical JSON for signed and hashed payloads.
- The signed-body rule (what the signature covers).
- Binary field encoding on the wire (base64url, no padding).
- ECDSA signature format (P-256, raw P1363).
- AES-256-GCM authenticated encryption (nonce, tag, layout).
- HKDF-SHA256 inside the snapshot-key wrap (salt, info, length prefixes).
- AEAD AAD for the wrapped snapshot key.
- The ledger hash chain (`entry_hash`, genesis).
- The v0.1 versioning rule for cryptographic labels and algorithm identifiers.

It does not cover transport framing, authentication tokens, or storage layout. Those are downstream concerns.

## Canonical JSON

Every signed payload and every payload fed into a SHA-256 hash MUST be serialized as **canonical JSON**.

Canonical JSON rules:

- **Key ordering**: sort all object keys lexicographically by their UTF-8 byte sequence, recursively at every nesting level.
- **Separators**: `","` between elements and `":"` between key and value. No additional whitespace anywhere.
- **Encoding**: UTF-8. `ensure_ascii = false` — non-ASCII characters are emitted as UTF-8 bytes, not `\uXXXX` escapes.
- **Trailing newline**: none. The output ends at the final `}` or `]`.
- **Floats**: reject `NaN`, `+Infinity`, `-Infinity` during both encode and decode. They MUST NOT appear in any signed or hashed payload.
- **Duplicate keys**: reject at decode time. A JSON document with two entries for the same key at the same level is invalid.

Python reference (illustrative):

```python
json.dumps(
    payload,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
```

Swift reference (illustrative): use a canonical encoder that sorts keys lexicographically, emits minified separators, encodes as UTF-8, and rejects non-finite floats. `JSONEncoder.OutputFormatting.sortedKeys` alone is not sufficient — also set `.withoutEscapingSlashes` is not required, but the encoder MUST NOT emit pretty-printing whitespace and MUST NOT append a trailing newline.

### Signed-body rule

For every payload type that carries a signature, the signed body is defined as:

> `signed_body = canonical_json(full_payload minus the *_signature field)`

The `*_signature` field is **the single field excluded** from the bytes that the signature covers. All other fields, including `type`, `version`, identifiers, public keys, timestamps, nonces, and hashes, are present in the signed body.

Applied to each payload type:

| Payload | Signature field excluded from signed body |
| --- | --- |
| `snapshot_commitment` | `owner_signature` |
| `witness_attestation` | `witness_signature` |
| `key_grant` | `grant_signature` |
| `report` | `report_signature` |
| `freeze` | `freeze_signature` |

The signing operation is:

```
signature_bytes = ECDSA_P256_SHA256_sign(signing_private_key, signed_body)
payload[signature_field] = base64url_no_pad(signature_bytes)
```

Verification reverses the process: re-serialize the received payload minus its `*_signature` field as canonical JSON, then verify the decoded signature bytes against that body using the signer's public key.

## Binary field encoding on the wire

Every field that carries binary content as a JSON string MUST be encoded as **base64url without padding** (RFC 4648 §5, with `=` padding stripped).

Required encoding: base64url, no padding. **Padded base64 input MUST be rejected** at decode time.

Fields covered, by schema:

| Schema | Field | Binary content |
| --- | --- | --- |
| `snapshot_commitment` | `ciphertext_hash` | SHA-256 digest (32 bytes) |
| `snapshot_commitment` | `owner_signing_public_key` | P-256 public key, 65 bytes uncompressed (`0x04 \|\| X \|\| Y`) |
| `snapshot_commitment` | `owner_encryption_public_key` | P-256 public key, 65 bytes uncompressed |
| `snapshot_commitment` | `session_nonce` | 32 random bytes |
| `snapshot_commitment` | `owner_signature` | ECDSA P1363 signature, 64 bytes |
| `witness_attestation` | `ciphertext_hash` | SHA-256 digest (32 bytes) |
| `witness_attestation` | `session_nonce` | 32 random bytes |
| `witness_attestation` | `owner_signing_public_key` | P-256 public key, 65 bytes uncompressed |
| `witness_attestation` | `witness_signing_public_key` | P-256 public key, 65 bytes uncompressed |
| `witness_attestation` | `witness_signature` | ECDSA P1363 signature, 64 bytes |
| `ledger_entry` | `payload_hash` | SHA-256 digest (32 bytes) |
| `ledger_entry` | `previous_entry_hash` | SHA-256 digest (32 bytes); 32 zero bytes for genesis |
| `ledger_entry` | `entry_hash` | SHA-256 digest (32 bytes) |
| `key_grant` | `recipient_encryption_public_key` | P-256 public key, 65 bytes uncompressed |
| `key_grant` | `wrapped_snapshot_key` | `nonce \|\| ciphertext \|\| tag` from AES-256-GCM (see [AES-256-GCM](#aes-256-gcm)) |
| `key_grant` | `granted_by_signing_public_key` | P-256 public key, 65 bytes uncompressed |
| `key_grant` | `grant_signature` | ECDSA P1363 signature, 64 bytes |

Notes:

- `verification_report` carries no binary fields; it is purely descriptive.
- `report` and `freeze` payloads follow the same rule for their signature and public-key fields.
- Identifiers (`snapshot_id`, `ledger_entry_id`, `grant_id`, `report_id`, `freeze_id`) are opaque ASCII strings, not binary, and are emitted verbatim (not base64url-encoded).
- Timestamps (`*_timestamp`) are ISO-8601 UTC strings with a trailing `Z` (e.g. `2026-05-15T00:00:00Z`), as specified in `04_protocol_overview.md`.

## ECDSA

All signatures in the protocol are produced with **ECDSA over P-256 with SHA-256** (FIPS 186-4, NIST P-256 / secp256r1).

Signature format on the wire: **raw P1363**, exactly 64 bytes — the concatenation of `r` and `s`, each big-endian and left-padded to 32 bytes.

**DER-encoded ECDSA signatures are explicitly rejected.**

Rationale:

- DER is variable-length; identical signatures admit multiple valid encodings. Canonical hashing of payloads that contain a signature field (e.g. for ledger `payload_hash`) requires a single byte-exact representation.
- DER decoders are a recurring source of parsing bugs and ambiguity (length-prefix handling, leading-zero rules). Raw P1363 has none of these properties.
- iOS CryptoKit emits raw P1363 by default (`P256.Signing.ECDSASignature.rawRepresentation`). The Python `cryptography` library emits DER by default; backend code MUST convert to and from raw P1363 at the protocol boundary and reject DER on input.

A receiver MUST reject any signature that is not exactly 64 bytes after base64url decoding.

## AES-256-GCM

All authenticated encryption in the protocol uses **AES-256-GCM** (NIST SP 800-38D).

Locked parameters:

- **Key size**: 256 bits.
- **Nonce**: **96 bits (12 bytes), random** per encryption operation, drawn from a cryptographically secure RNG.
- **Tag**: **128 bits (16 bytes), untruncated.** Truncated tags are rejected.
- **Wire layout**: `nonce \|\| ciphertext \|\| tag`, in that exact order, then base64url-no-pad encoded.

A receiver MUST:

- Reject any AEAD input shorter than `12 + tag_length` bytes (no room for nonce + tag).
- Reject any AEAD input where the trailing tag is shorter than 16 bytes.
- Treat tag verification failure as a hard error — never return partial plaintext on failure.

This applies to both the per-snapshot bundle encryption (where the AEAD output is the encrypted evidence, not on the wire as a JSON field) and the wrapped snapshot key inside `key_grant.wrapped_snapshot_key`.

## HKDF-SHA256 (snapshot key wrap)

Wrapping a per-snapshot symmetric key for a recipient uses **ECDH(P-256) + HKDF-SHA256 + AES-256-GCM**. The `key_grant.wrapping_algorithm` identifier for this v0.1 construction is `"ecdhp256+aesgcm256"`.

The full construction:

1. **ECDH**: derive `shared_secret = ECDH(owner_encryption_private_key, recipient_encryption_public_key)`. The shared secret is the 32-byte X coordinate of the resulting point (raw shared secret; no KDF inside ECDH itself).
2. **HKDF-SHA256**: derive a 32-byte wrapping key from `shared_secret` using the locked `salt` and `info` below.
3. **AEAD**: encrypt the 32-byte snapshot key with AES-256-GCM under the derived wrapping key, using the locked AAD below.
4. **Wire**: `wrapped_snapshot_key = base64url_no_pad(nonce || ciphertext || tag)`.

### Locked HKDF parameters

```
salt = b"pke/v0.1/keywrap/salt"

info = b"pke/v0.1/keywrap/info"
     || u16be(len(snapshot_id_utf8)) || snapshot_id_utf8
     || u16be(len(recipient_pub_raw)) || recipient_pub_raw
```

Where:

- `b"…"` denotes the literal UTF-8 byte sequence of the string between the quotes. No null terminator.
- `u16be(n)` is the unsigned 16-bit big-endian encoding of `n`, exactly 2 bytes.
- `snapshot_id_utf8` is the UTF-8 byte sequence of the `snapshot_id` string (no quoting, no escaping).
- `recipient_pub_raw` is the recipient's encryption public key as a **65-byte uncompressed P-256 point**: `0x04 || X || Y`, where `X` and `Y` are each 32 bytes big-endian. This is the same byte form that is base64url-encoded into `recipient_encryption_public_key` on the wire.

HKDF output length: 32 bytes (the AES-256-GCM key).

### Why the length-prefixed `info`

The `info` parameter binds the derived wrapping key to the exact `(snapshot_id, recipient_public_key)` pair. Length prefixes (`u16be`) make the concatenation injective: two distinct `(snapshot_id, recipient_pub)` pairs always produce distinct `info` bytes, even if one identifier could be a substring of another. Without length prefixes, naive concatenation admits collisions (e.g. `("ab", "cd")` and `("a", "bcd")` would otherwise produce identical bytes).

Implementations MUST encode `info` exactly as shown, byte for byte, with no separators or padding beyond the explicit length fields.

### Locked AEAD AAD for the wrapped snapshot key

```
aad = b"pke/v0.1/keywrap/aad"
    || u16be(len(snapshot_id_utf8)) || snapshot_id_utf8
```

The AAD binds the AEAD ciphertext to the `snapshot_id` context. This prevents **wrap-swap attacks**: an attacker who intercepts two `key_grant` records cannot substitute one `wrapped_snapshot_key` for another, because each AEAD ciphertext is bound to its own `snapshot_id` and tag verification will fail on substitution.

The AAD does not include the recipient public key because that is already pinned by the HKDF `info` — substituting the recipient changes the wrapping key itself, so the AEAD tag would fail regardless of AAD.

The AAD is passed to AES-256-GCM as additional authenticated data; it is not included in the ciphertext bytes and not transmitted over the wire. Both sides reconstruct it from the `snapshot_id` in the `key_grant`.

## Hash chain

The ledger is an append-only chain. Each entry's `entry_hash` covers the entire entry **except** the `entry_hash` field itself.

```
entry_body = canonical_json(ledger_entry minus the entry_hash field)
entry_hash = SHA256(entry_body)
```

The `entry_hash` is then base64url-no-pad encoded into the `entry_hash` field of the emitted ledger entry.

The `previous_entry_hash` field of each entry is the `entry_hash` of the immediately preceding ledger entry, also base64url-no-pad encoded.

### Genesis

The first ledger entry in the chain MUST set:

```
previous_entry_hash = base64url_no_pad(b"\x00" * 32)
```

That is, the base64url-no-pad encoding of 32 zero bytes. This is a fixed, well-known string and serves as the chain's anchor.

A verifier MUST reject a chain whose first entry's `previous_entry_hash` is not this exact value, and MUST reject any subsequent entry whose `previous_entry_hash` does not match the prior entry's `entry_hash` byte-for-byte.

The `payload_hash` field of a ledger entry is the SHA-256 digest of the canonical-JSON serialization of the originating payload (e.g. the `snapshot_commitment`, `witness_attestation`, `key_grant`, `report`, or `freeze` that the entry records). It is base64url-no-pad encoded on the wire.

## Versioning

Every cryptographic label introduced in this spec carries the literal `v0.1` segment:

- HKDF `salt`: `"pke/v0.1/keywrap/salt"`
- HKDF `info` prefix: `"pke/v0.1/keywrap/info"`
- AEAD `aad` prefix: `"pke/v0.1/keywrap/aad"`
- Key-grant `wrapping_algorithm` identifier: `"ecdhp256+aesgcm256"` (v0.1 construction)

Any future change to **any** of the following:

- canonical-JSON rules,
- the signed-body rule,
- binary field encoding,
- ECDSA format,
- AES-GCM parameters (nonce length, tag length, layout),
- HKDF parameters (`salt`, `info` structure, hash, output length),
- the AEAD `aad`,
- the hash-chain construction,

MUST mint a **new** label set (e.g. `pke/v0.2/keywrap/*`) and a **new** `wrapping_algorithm` identifier. The existing v0.1 values are never mutated in place. This guarantees that any signature, hash, or wrapped key produced under v0.1 remains independently verifiable forever, even after the protocol evolves.

Implementations MUST refuse to verify a payload whose embedded `version` does not match the version of the construction they implement.

## Edge cases and rejection rules

| Scenario | Required behavior |
| --- | --- |
| `NaN`, `+Infinity`, or `-Infinity` in a payload to be encoded | Reject. Raise an error; do not emit. |
| Duplicate keys in JSON to be decoded as a signed body | Reject at decode time. |
| Base64url input with `=` padding | Reject. |
| Base64url input with non-alphabet characters (including standard `+` / `/`) | Reject. |
| ECDSA signature decoded to a length other than 64 bytes | Reject. |
| DER-encoded ECDSA signature on the wire | Reject. |
| AES-GCM tag shorter than 16 bytes | Reject. |
| AES-GCM input shorter than `12 + 16` bytes | Reject. |
| First-ever ledger entry | `previous_entry_hash` MUST be `base64url_no_pad(32 zero bytes)`. |
| Subsequent ledger entry whose `previous_entry_hash` does not equal the prior `entry_hash` | Reject the chain. |
| Two distinct `(snapshot_id, recipient_pub)` pairs producing the same HKDF `info` | Impossible by construction: length-prefixed components guarantee distinct bytes. |
| Future need to change any locked construction | Mint a new version label and `wrapping_algorithm`; never mutate v0.1 values. |
| Payload `version` field does not match the implementation's version | Reject. |

## STRIDE notes

| Threat | Applicable? | How this spec mitigates |
| --- | --- | --- |
| **Spoofing** | Yes | ECDSA over canonical bytes binds every commitment, attestation, and grant to a specific device public key. |
| **Tampering** | Yes | The hash chain, `ciphertext_hash`, and signed bodies make any in-flight or at-rest modification detectable. |
| **Repudiation** | Yes | Signed payloads and the ledger chain make custody actions non-repudiable to the signing device key. |
| **Information disclosure** | Partial | This spec respects the `metadata_policy` boundary; private content lives only inside encrypted bundles and wrapped keys, both of which use AES-256-GCM with full-length tags. The spec does not weaken any disclosure boundary. |
| **Denial of service** | N/A | Doc-only; runtime DoS surfaces are downstream concerns. |
| **Elevation of privilege** | N/A | No authorization model is touched by the spec itself. |

## Cross-references

- `04_protocol_overview.md` — payload shapes, event types, replay-protection rules, timestamp semantics.
- `15_implementation_notes_public.md` — platform library mapping (CryptoKit, `cryptography`); identity lifecycle.
- `src/shared/schemas/*.json` — field-level provenance for every binary field listed in [Binary field encoding on the wire](#binary-field-encoding-on-the-wire).
- `06_threat_model.md` — broader assets and trust boundaries that this spec sits inside.

## Status

v0.1, locked. Any change to the constructions above requires a version bump and a new `wrapping_algorithm` identifier.
