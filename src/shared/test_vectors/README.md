# Test Vectors

## Purpose

This directory holds per-primitive test-vector bundles used to verify cross-implementation parity (iOS and Python backend) for low-level cryptographic and encoding primitives.

Each bundle pins one input/output pair so that any conforming implementation must produce identical bytes for identical inputs. Vectors here encode the canonical-bytes contract defined in HLAM-3.

## Scope

In scope:

- single-primitive vectors (e.g., hash, signature verify, key wrap, canonical encoding, HKDF derivation),
- one minimal negative case per primitive directory.

Out of scope:

- full sign-then-wrap-then-chain lifecycle fixtures (these belong to HLAM-10),
- end-to-end protocol scenarios,
- multi-step ledger replay fixtures.

A vector that crosses more than one primitive boundary does not belong here.

## Bundle shape

Every test-vector file is a single JSON object with exactly the following top-level shape:

```json
{
  "name": "<descriptive case name>",
  "inputs": { ... per-primitive input fields ... },
  "expected": { ... per-primitive expected output fields ... },
  "valid": true | false,
  "notes": "<optional human-readable note>"
}
```

### Top-level keys

| Key | Type | Purpose |
|-----|------|---------|
| `name` | string | Descriptive case identifier, unique within the primitive directory. Used in test runner output. |
| `inputs` | object | Per-primitive input fields supplied to the primitive under test. Field set is defined by the primitive's own contract. |
| `expected` | object | Per-primitive expected output fields. For positive cases, the primitive must produce these bytes. For negative cases, this records the value the implementation should reject or the failure mode it should report. |
| `valid` | boolean | Whether the bundle is a positive (`true`) or negative (`false`) case. See "Negative fixtures" below. |
| `notes` | string | Optional human-readable note. May describe provenance, rationale, or known cross-references. Omit if empty. |

## Conventions

1. **One case per file.** Each `.json` file contains exactly one bundle object. Do not group multiple cases into arrays. File name should match `name` (kebab- or snake-cased) with a `.json` suffix.
2. **Lowercase hex for binary fields.** All binary values inside `inputs` and `expected` are encoded as lowercase hexadecimal strings without prefix, separators, or whitespace. No base64, no base64url, no mixed case. This applies to keys, signatures, hashes, ciphertexts, nonces, salts, and canonical-byte blobs.
3. **Stable field names.** Field names inside `inputs` and `expected` are fixed per primitive and must not vary case-by-case.
4. **Deterministic inputs.** Vectors must not depend on time, randomness, or environment. Any nonce, salt, or ephemeral key is pinned in `inputs`.
5. **Per-primitive subdirectory.** Each primitive lives in its own subdirectory (added by later tickets). This README defines the bundle shape only; it does not enumerate primitives.

## Negative fixtures

Each primitive directory contains exactly **one minimal negative fixture** with `valid: false`.

Rationale:

- a single negative case proves the implementation rejects the most obvious malformed input for that primitive,
- multiple negative variants are out of scope here and belong to dedicated fuzz or property tests,
- keeping the negative set minimal prevents this directory from drifting into a general-purpose failure-case catalog,
- the `valid` flag lets a single parity runner branch between "produce equal output" and "reject input" without per-primitive runner code.

The negative fixture's `expected` object records the expected rejection signal (e.g., the verifier returning false, or the canonical encoder raising a defined error). `notes` should state which failure mode is being asserted.

## Related

- **HLAM-3** — canonical-encoding specification. Defines the canonical-bytes contract that these vectors encode and pin.
- **HLAM-10** — full lifecycle fixtures (sign, wrap, chain). Out of scope for this directory.
- `src/shared/schemas/` — JSON Schemas for protocol payloads (separate from primitive vectors).
