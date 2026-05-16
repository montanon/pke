# System Architecture

## Overview

```text
iOS App
  ├── Capture Service
  ├── Device Identity Service
  ├── Crypto Service
  ├── Attestation Service
  ├── Ledger Client
  ├── Key Grant Client
  └── Verification Service

Backend
  ├── API Service
  ├── Encrypted Blob Storage
  ├── Custody Ledger
  ├── Attestation Registry
  ├── Identity Registry
  ├── Key Grant Registry
  └── Report/Freeze Registry

Protocol
  ├── Snapshot Commitment
  ├── Witness Attestation
  ├── Ledger Entry
  ├── Key Grant
  └── Verification Report
```

## iOS app modules

### Capture Service

Captures live media and metadata inside the app. The MVP should support live photo capture and optional coarse/private location metadata. It should not import existing files.

### Device Identity Service

Generates and stores local cryptographic identities:

- signing keypair for commitments and attestations,
- encryption or key-agreement keypair for key grants.

Private keys remain local.

### Crypto Service

Performs:

- per-snapshot symmetric key generation,
- local encryption,
- ciphertext hashing,
- payload signing,
- signature verification,
- snapshot-key wrapping and unwrapping,
- local decryption for authorized recipients.

### Attestation Service

Manages nearby witness sessions. A witness receives a commitment payload and signs it without seeing decrypted content.

### Ledger Client

Submits and retrieves custody events and verifies ledger integrity where possible.

### Key Grant Client

Creates and retrieves wrapped snapshot keys for authorized recipients.

### Verification Service

Produces a human-readable custody report by verifying hashes, signatures, attestations, ledger entries, and key grants.

## Backend modules

### API Service

Provides endpoints for snapshots, attestations, custody trails, identities, key grants, and reports.

### Encrypted Blob Storage

Stores encrypted snapshot blobs only. Plaintext evidence and plaintext snapshot keys must not be stored.

### Custody Ledger

Stores append-only custody events using hash chaining.

### Attestation Registry

Stores witness attestations linked to snapshot commitments.

### Identity Registry

Stores public keys and optional public labels only.

### Key Grant Registry

Stores wrapped snapshot keys for authorized recipients.

### Report/Freeze Registry

Stores metadata-level reports and freeze states.

## Data flow

```text
1. Owner captures live snapshot.
2. App creates snapshot bundle.
3. App generates per-snapshot symmetric key.
4. App encrypts bundle locally.
5. App hashes ciphertext.
6. App signs snapshot commitment.
7. Nearby witness signs commitment.
8. Backend stores encrypted blob and custody events.
9. Owner grants recipient access by wrapping snapshot key.
10. Recipient verifies custody trail.
11. Recipient decrypts locally if authorized.
```

## Trust boundary

The backend coordinates storage and retrieval but should not be trusted with plaintext evidence, plaintext keys, or unverified custody claims. Clients should verify cryptographic evidence locally whenever possible.
