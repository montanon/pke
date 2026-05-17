# Public Implementation Notes

## Purpose

This document captures public implementation guidance without exposing sensitive operational details.

## Recommended MVP implementation

### iOS modules

```text
CaptureService
DeviceIdentityService
CryptoService
AttestationService
LedgerClient
KeyGrantClient
VerificationService
```

### Cryptography

Use standard platform cryptographic libraries. Avoid custom cryptographic primitives.

#### Authenticated encryption

Encrypt snapshot bundles with AES-256-GCM using a per-snapshot symmetric key. On iOS: `CryptoKit AES.GCM.seal()` / `AES.GCM.open()`. Per-snapshot key: 256-bit random via `SymmetricKey(size: .bits256)`.

#### Hashing

Hash ciphertext with SHA-256. On iOS: `CryptoKit SHA256.hash(data:)`. Used for `ciphertext_hash` in snapshot commitments and for the hash chain in ledger entries.

#### Digital signatures

Sign commitments and attestations with ECDSA over P-256. On iOS: `CryptoKit P256.Signing.PrivateKey`. Owner signs snapshot commitments; witnesses sign attestations; grantors sign key grants.

#### Key agreement and wrapping

Wrap per-snapshot keys for recipients using ECDH key agreement (P-256). On iOS: `CryptoKit P256.KeyAgreement.PrivateKey`. Derive a shared secret between owner and recipient encryption keys, use HKDF to derive a wrapping key, then wrap the snapshot key with AES-256-GCM. The HKDF `info` and `salt` parameters are implementation-defined; these must be specified consistently between iOS and backend for interoperability.

#### Encoding

Public keys and signatures should be encoded as base64url for JSON payloads. Use a consistent encoding (DER or raw P1363) for ECDSA signatures.

#### Backend verification

The backend (Python) may verify signatures using the `cryptography` library with matching P-256 / SHA-256 parameters.

### Secure storage

Private keys should remain on-device. Use secure local storage appropriate to the platform. Do not commit keys, certificates, profiles, or secrets.

### Identity lifecycle

The device generates a `P256.Signing.PrivateKey` and a `P256.KeyAgreement.PrivateKey` at first launch. Private keys are stored in iOS Keychain (or Secure Enclave for future hardening). Public keys are registered with the backend identity registry.

The MVP does not implement key rotation or key revocation. These are future-work items (see `10_roadmap.md`).

### Timestamp handling

All timestamps use ISO-8601 UTC format (e.g., `2026-05-15T00:00:00Z`).

Device-reported timestamps (`capture_timestamp`, `witness_timestamp`, `grant_timestamp`) are advisory and may be manipulated. Backend-assigned timestamps (`entry_timestamp`) provide ordering but are not cryptographically trusted.

The MVP should reject witness attestations with timestamps more than 5 minutes from backend receipt time.

### Nearby attestation

Use native nearby-device communication where possible. The transport should move commitment and attestation payloads. It should not own cryptographic policy.

### Backend

The backend stores:

- encrypted blobs,
- public keys,
- ledger entries,
- witness attestations,
- wrapped keys,
- report/freeze metadata.

The backend should not store:

- plaintext evidence,
- plaintext snapshot keys,
- private keys,
- production secrets in the repository.

## Repository hygiene

Use:

- `.env.sample` instead of `.env`,
- secret scanning,
- dependency scanning,
- synthetic test fixtures,
- public-safe protocol examples,
- manual review for PII.

## Do not publish

Do not publish:

- Apple certificates,
- provisioning profiles,
- real backend secrets,
- real database dumps,
- real media captures,
- real device identifiers,
- logs containing private data.

## Future implementation direction

A future production-grade system may introduce:

- portable protocol core,
- public verification CLI,
- transparency log,
- public-chain anchoring,
- organization workflows,
- stronger identity model,
- hardware-backed protections.

These are future directions, not MVP requirements.
