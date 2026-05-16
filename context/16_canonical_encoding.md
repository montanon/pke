# Canonical Encoding (v0.1)

## Purpose

This document is the single authoritative source for the byte-level encoding of every signed, hashed, and wrapped value in the PKE protocol at version `v0.1`.

Two independent implementations — Swift `swift-crypto` / Apple `CryptoKit` on iOS and Python `cryptography` on the backend — must be able to read this document and produce byte-identical output. Any value defined here is load-bearing. Changing it after `v0.1` ships silently invalidates every prior signature, ledger entry, and key grant. Future construction changes mint a new `wrapping_algorithm` identifier instead of mutating values defined here.

This spec applies to the JSON Schemas under `src/shared/schemas/` and complements the protocol surface described in `04_protocol_overview.md` and `15_implementation_notes_public.md`.

## Scope

In scope:

- canonical JSON serialization of all signed payloads,
- the `signed_body` rule for every signed payload type,
- base64url-no-padding rules for every binary field on the wire,
- ECDSA signature encoding,
- AES-256-GCM bundle layout for encrypted snapshot data and wrapped keys,
- HKDF-SHA256 parameters used for the key wrap,
- AEAD AAD bytes used when sealing wrapped snapshot keys,
- ledger hash-chain construction and genesis value,
- versioning rule for protocol labels.

Out of scope:

- transport-layer encoding (HTTP, MultipeerConnectivity),
- private-key storage formats,
- on-disk database layout,
- non-protocol logging or telemetry encodings.

## Canonical JSON

Every signed, hashed, or wrap-bound JSON payload is serialized through a single canonical form before bytes are produced for signing or hashing.

Rules:

- keys are sorted lexicographically by Unicode code point at every object level,
- separators are `","` and `":"` with no surrounding whitespace,
- output is UTF-8,
- non-ASCII characters are emitted as-is (no `\uXXXX` escaping unless required by JSON),
- numeric values must be finite — `NaN`, `Infinity`, and `-Infinity` are rejected on both encode and decode,
- duplicate keys are rejected at decode time,
- no trailing newline is appended,
- output is otherwise minified (no insignificant whitespace).

The canonical form is what gets signed, hashed, and AAD-bound. Pretty-printed or otherwise non-canonical bytes are never authenticated.

Reference implementations:

- Python: `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)` plus a duplicate-key check on parse.
- Swift: a deterministic encoder that emits sorted keys, the same separator policy, and rejects non-finite floats.

## Signed body

For every signed payload, the bytes that are signed are the canonical JSON of the payload with its signature field removed:

```text
signed_body = canonical_json(payload \ {<payload>_signature})
```

The signature field is then base64url-no-padding encoded and re-inserted before the payload is published on the wire.

The per-payload rule is:

| Payload | Signature field | signed_body |
|---|---|---|
| `snapshot_commitment` | `owner_signature` | full commitment minus `owner_signature` |
| `witness_attestation` | `witness_signature` | full attestation minus `witness_signature` |
| `key_grant` | `grant_signature` | full grant minus `grant_signature` |
| `ledger_entry` | (not signed) | hashing rule, see Hash chain |
| `verification_report` | (not signed) | informational output |

The `ledger_entry` payload is hashed, not signed. The `verification_report` is informational and carries no signature in `v0.1`.

## Binary fields on the wire

Every binary field carried inside a JSON payload is encoded as **base64url with no padding** (RFC 4648 §5 alphabet, `=` characters stripped). Padded inputs are rejected at decode time. Implementations must reject decode results whose length does not match the field's expected byte length.

The fields below are sourced from `src/shared/schemas/*.json`.

### Public keys (`*_public_key`)

| Schema | Field | Bytes |
|---|---|---|
| `snapshot_commitment.json` | `owner_signing_public_key` | 65-byte uncompressed P-256 (`0x04` ‖ X ‖ Y) |
| `snapshot_commitment.json` | `owner_encryption_public_key` | 65-byte uncompressed P-256 |
| `witness_attestation.json` | `owner_signing_public_key` | 65-byte uncompressed P-256 |
| `witness_attestation.json` | `witness_signing_public_key` | 65-byte uncompressed P-256 |
| `key_grant.json` | `recipient_encryption_public_key` | 65-byte uncompressed P-256 |
| `key_grant.json` | `granted_by_signing_public_key` | 65-byte uncompressed P-256 |

Public keys are always the SEC1 uncompressed point encoding. Compressed (`0x02`/`0x03` prefix) and ANSI X9.63 hybrid forms are rejected.

### Signatures (`*_signature`)

| Schema | Field | Bytes |
|---|---|---|
| `snapshot_commitment.json` | `owner_signature` | 64-byte raw P1363 ECDSA |
| `witness_attestation.json` | `witness_signature` | 64-byte raw P1363 ECDSA |
| `key_grant.json` | `grant_signature` | 64-byte raw P1363 ECDSA |

See ECDSA section.

### Hashes (`*_hash`)

| Schema | Field | Bytes |
|---|---|---|
| `snapshot_commitment.json` | `ciphertext_hash` | 32-byte SHA-256 of the encrypted snapshot bundle |
| `witness_attestation.json` | `ciphertext_hash` | 32-byte SHA-256, must equal the value in the commitment being attested |
| `ledger_entry.json` | `payload_hash` | 32-byte SHA-256 of the canonical payload referenced by the entry |
| `ledger_entry.json` | `previous_entry_hash` | 32-byte SHA-256 of the previous entry, or 32 zero bytes for the first entry |
| `ledger_entry.json` | `entry_hash` | 32-byte SHA-256, see Hash chain |

### Session nonces (`session_nonce`)

| Schema | Field | Bytes |
|---|---|---|
| `snapshot_commitment.json` | `session_nonce` | 16 random bytes |
| `witness_attestation.json` | `session_nonce` | 16 random bytes, must equal the commitment's `session_nonce` |

The session nonce is opaque random material used to bind a witness attestation to a specific commitment session. It is independent of the AES-GCM nonce defined below.

### Wrapped key material (`wrapped_snapshot_key`)

| Schema | Field | Bytes |
|---|---|---|
| `key_grant.json` | `wrapped_snapshot_key` | `nonce ‖ ciphertext ‖ tag` from AES-256-GCM (see AES-GCM section) |

## ECDSA

All `v0.1` ECDSA signatures are:

- curve: NIST P-256 (secp256r1),
- hash: SHA-256,
- encoding: **raw P1363** — the concatenation of the 32-byte big-endian `r` and the 32-byte big-endian `s`, for a fixed 64-byte signature.

DER-encoded ECDSA signatures are **explicitly rejected** on the wire. Rationale:

- DER encoding is variable-length and admits multiple valid encodings of the same `(r, s)` pair (leading-zero handling, length-byte padding), which complicates strict equality checks and reproducible signing fixtures,
- Raw P1363 is a fixed 64-byte container, so every implementation produces byte-identical outputs for byte-identical inputs,
- CryptoKit and `swift-crypto` expose P1363 directly (`P256.Signing.ECDSASignature.rawRepresentation`); the Python `cryptography` library produces DER by default and must convert to raw P1363 before emitting on the wire.

Public-key encoding on the wire is the 65-byte uncompressed SEC1 form documented above.

## AES-256-GCM

Used in two places: sealing the encrypted snapshot bundle, and sealing the wrapped snapshot key inside a key grant.

Parameters:

- key length: 256 bits,
- nonce: 96-bit (12-byte) random, freshly drawn per sealing operation,
- tag: 128-bit (16-byte), **untruncated**,
- wire layout: `nonce ‖ ciphertext ‖ tag`.

Implementations must reject any AES-GCM input whose tag length is less than 128 bits and any wire blob whose length is less than `12 + 16 = 28` bytes.

Note: `swift-crypto` / `CryptoKit` `AES.GCM.SealedBox` exposes `combined` which already produces the `nonce ‖ ct ‖ tag` layout. Python `cryptography` must concatenate them manually.

## HKDF-SHA256 (key wrap)

The wrapping key used to AES-GCM-seal a `wrapped_snapshot_key` is derived from an ECDH-P256 shared secret via HKDF-SHA256.

Parameters:

```text
ikm  = ECDH(owner_encryption_private_key, recipient_encryption_public_key)
hash = SHA-256
salt = b"pke/v0.1/keywrap/salt"
info = b"pke/v0.1/keywrap/info"
     ‖ u16be(len(snapshot_id_utf8)) ‖ snapshot_id_utf8
     ‖ u16be(len(recipient_pub_raw)) ‖ recipient_pub_raw
L    = 32   # output 32 bytes -> AES-256 key
```

Where:

- `snapshot_id_utf8` is the UTF-8 encoding of the `snapshot_id` string from `key_grant.json`,
- `recipient_pub_raw` is the **65-byte uncompressed P-256** encoding of `recipient_encryption_public_key` (`0x04` ‖ X ‖ Y),
- `u16be(n)` is the unsigned 16-bit big-endian encoding of `n`. Inputs whose length exceeds `0xFFFF` are rejected.

The length-prefixed structure of `info` is mandatory: it guarantees that two distinct `(snapshot_id, recipient_pub)` pairs cannot collide into the same `info` bytes by adversarial choice of `snapshot_id`.

`wrapping_algorithm` in `key_grant.json` for the `v0.1` construction is the string `"ecdhp256+aesgcm256"`.

## AEAD AAD (wrapping)

When sealing the wrapped snapshot key with AES-256-GCM, the AAD is:

```text
aad = b"pke/v0.1/keywrap/aad"
    ‖ u16be(len(snapshot_id_utf8)) ‖ snapshot_id_utf8
```

This AAD binds the wrap to its `snapshot_id`. Rationale: without an AAD that names the snapshot, an attacker who held a valid wrap for snapshot `A` could republish it as a wrap for snapshot `B` (a wrap-swap attack) since the ciphertext alone reveals nothing about which snapshot it grants access to. Binding the AAD to the `snapshot_id` makes any such cross-snapshot reuse fail at GCM tag verification.

The AAD is not transmitted; both sides reconstruct it from `snapshot_id`.

The encrypted snapshot bundle itself (the AES-GCM operation whose digest is `ciphertext_hash`) uses an empty AAD in `v0.1`; integrity of the surrounding commitment is provided by `owner_signature` over the commitment payload, which itself carries `ciphertext_hash`.

## Hash chain

Each ledger entry is hashed over its canonical bytes minus its `entry_hash` field:

```text
entry_hash = SHA-256(canonical_json(ledger_entry \ {entry_hash}))
```

The `previous_entry_hash` field references the prior entry's `entry_hash`. For the very first ledger entry, `previous_entry_hash` is **32 zero bytes**, base64url-no-padding encoded (i.e. `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`).

Verifiers recompute `entry_hash` from canonical bytes and check the chain end-to-end. Any divergence breaks verification at the diverging entry.

`payload_hash` inside a ledger entry is the SHA-256 of the canonical JSON of the referenced payload (commitment, attestation, grant, report, or freeze) with that payload's own signature field included — `payload_hash` covers the wire-form payload, not its `signed_body`.

## Versioning

Every label that appears inside a `v0.1` construction carries the literal `v0.1` substring:

- HKDF `salt`: `b"pke/v0.1/keywrap/salt"`
- HKDF `info` prefix: `b"pke/v0.1/keywrap/info"`
- AEAD AAD prefix: `b"pke/v0.1/keywrap/aad"`

Any future change to these constructions — different curve, different AEAD, different KDF, different `info` shape — mints a **new** `wrapping_algorithm` identifier (e.g. `"ecdhp256+aesgcm256+v0.2"` or a freshly named scheme). The `v0.1` constants are immutable. Implementations must refuse to consume a payload whose `wrapping_algorithm` they do not recognize.

Payload-level `version` strings (e.g. `"version": "0.1"` inside `snapshot_commitment`, `witness_attestation`, `key_grant`, `ledger_entry`) are likewise frozen for `v0.1`. A future schema change mints a new `version` value.

## Rejection summary

A conforming implementation rejects, on decode or verify:

- canonical JSON with `NaN`, `Infinity`, `-Infinity`,
- canonical JSON with duplicate keys,
- base64url input with padding (`=` characters present),
- base64url output whose decoded length does not match the field's expected byte length,
- DER-encoded ECDSA signatures on the wire,
- AES-GCM tags shorter than 128 bits,
- wrap blobs whose length is less than 28 bytes (12-byte nonce + 16-byte tag minimum),
- public keys whose first byte is not `0x04` or whose length is not 65 bytes,
- HKDF `info` components whose length exceeds `0xFFFF`,
- payloads whose `wrapping_algorithm` is unrecognized.

## Cross-references

- `04_protocol_overview.md` — payload shapes, event types, replay protection.
- `05_data_model_public.md` — public data model surfaces these fields map onto.
- `15_implementation_notes_public.md` — recommended platform libraries (CryptoKit, `cryptography`) and identity lifecycle.
- `src/shared/schemas/*.json` — authoritative field presence and types (this document defines the byte-level encoding of those fields).
