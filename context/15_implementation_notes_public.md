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

Required operations:

- authenticated encryption for snapshot bundles,
- secure hashing for ciphertext commitments,
- digital signatures for commitments and attestations,
- hybrid encryption or key agreement for key grants.

### Secure storage

Private keys should remain on-device. Use secure local storage appropriate to the platform. Do not commit keys, certificates, profiles, or secrets.

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

- `.env.example` instead of `.env`,
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
