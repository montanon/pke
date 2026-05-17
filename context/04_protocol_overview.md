# Protocol Overview

## Purpose

This document defines public protocol concepts for the MVP.

The protocol supports local evidence encryption, cryptographic commitment, owner signature, nearby witness attestation, append-only custody ledger, selective disclosure, and verification report generation.

All examples use synthetic placeholder values.

## Canonical payloads

Signed payloads should use deterministic canonical representation.

Principles:

- include `type` and `version`,
- exclude `signature` from the signed body,
- use stable field names,
- use ISO-8601 timestamps,
- use base64url or hex consistently,
- include nonces for replay protection,
- avoid unordered maps unless canonicalized.

## Event types

The `event_type` field in ledger entries must be one of:

- `SNAPSHOT_COMMITTED` — a new encrypted snapshot was committed to the ledger.
- `WITNESS_ATTESTED` — a nearby witness signed an attestation for a commitment.
- `KEY_GRANTED` — the owner wrapped a snapshot key for an authorized recipient.
- `REPORTED` — a user reported a snapshot record at the metadata level.
- `FROZEN` — future key grants for a snapshot were frozen.

## Snapshot Commitment

```json
{
  "type": "snapshot_commitment",
  "version": "0.1",
  "snapshot_id": "snap_test_001",
  "ciphertext_hash": "sha256_test_hash_001",
  "owner_signing_public_key": "owner_test_signing_public_key_001",
  "owner_encryption_public_key": "owner_test_encryption_public_key_001",
  "capture_timestamp": "2026-05-15T00:00:00Z",
  "metadata_policy": {
    "location_public": false,
    "location_precision": "not_public",
    "media_type": "photo"
  },
  "session_nonce": "session_nonce_test_001",
  "owner_signature": "owner_test_signature_001"
}
```

## Witness Attestation

A witness attestation means a witness device signed a commitment payload during a nearby session. It does not mean the witness viewed or verified the content.

```json
{
  "type": "witness_attestation",
  "version": "0.1",
  "snapshot_id": "snap_test_001",
  "ciphertext_hash": "sha256_test_hash_001",
  "session_nonce": "session_nonce_test_001",
  "owner_signing_public_key": "owner_test_signing_public_key_001",
  "witness_signing_public_key": "witness_test_signing_public_key_001",
  "witness_timestamp": "2026-05-15T00:00:30Z",
  "transport": "multipeerconnectivity",
  "proximity_claim": {
    "method": "nearby_session",
    "exact_location_public": false
  },
  "witness_signature": "witness_test_signature_001"
}
```

## Ledger Entry

Each custody event produces a ledger entry. The `event_type` must be one of the types listed in the Event types section above.

```json
{
  "type": "ledger_entry",
  "version": "0.1",
  "ledger_entry_id": "ledger_entry_test_001",
  "event_type": "SNAPSHOT_COMMITTED",
  "snapshot_id": "snap_test_001",
  "payload_hash": "sha256_payload_hash_test_001",
  "previous_entry_hash": "sha256_previous_entry_hash_test_001",
  "entry_timestamp": "2026-05-15T00:00:35Z",
  "entry_hash": "sha256_entry_hash_test_001"
}
```

## Key Grant

```json
{
  "type": "key_grant",
  "version": "0.1",
  "grant_id": "grant_test_001",
  "snapshot_id": "snap_test_001",
  "recipient_encryption_public_key": "recipient_test_encryption_public_key_001",
  "wrapped_snapshot_key": "wrapped_key_test_001",
  "wrapping_algorithm": "ecdhp256+aesgcm256",
  "granted_by_signing_public_key": "owner_test_signing_public_key_001",
  "grant_timestamp": "2026-05-15T00:01:00Z",
  "grant_signature": "grant_test_signature_001"
}
```

### Wrapping algorithm guidance

The MVP should use ECDH key agreement (P-256) to derive a shared secret between the owner and recipient encryption keys, then derive a wrapping key via HKDF, then wrap the per-snapshot symmetric key with AES-256-GCM using the derived wrapping key. On iOS, this maps to CryptoKit `P256.KeyAgreement` and `AES.GCM`. The `wrapping_algorithm` field should be set to `"ecdhp256+aesgcm256"` to identify this construction.

## Report

A report is a metadata-level action that flags a snapshot for review. It does not require backend decryption. The backend marks the snapshot as reported and creates a `REPORTED` ledger entry.

```json
{
  "type": "report",
  "version": "0.1",
  "report_id": "report_test_001",
  "snapshot_id": "snap_test_001",
  "reason_category": "abuse_concern",
  "reported_by_signing_public_key": "reporter_test_signing_public_key_001",
  "report_timestamp": "2026-05-15T00:02:00Z",
  "report_signature": "report_test_signature_001"
}
```

The `reason_category` may be one of: `abuse_concern`, `legal_request`, `owner_request`, `other`.

## Freeze

A freeze restricts future key grants for a reported snapshot. It creates a `FROZEN` ledger entry. Existing custody metadata and encrypted blobs are preserved. A freeze may be triggered by a report or by an administrative action.

```json
{
  "type": "freeze",
  "version": "0.1",
  "freeze_id": "freeze_test_001",
  "snapshot_id": "snap_test_001",
  "triggered_by": "report_test_001",
  "frozen_by_signing_public_key": "system_test_signing_public_key_001",
  "freeze_timestamp": "2026-05-15T00:02:05Z",
  "freeze_signature": "freeze_test_signature_001"
}
```

## Verification Report

```json
{
  "type": "verification_report",
  "version": "0.1",
  "snapshot_id": "snap_test_001",
  "results": {
    "ciphertext_hash_verified": true,
    "owner_signature_verified": true,
    "witness_signatures_verified": true,
    "ledger_hash_chain_verified": true,
    "recipient_key_grant_verified": true
  },
  "attestation_summary": {
    "witness_count": 2,
    "transport": "multipeerconnectivity",
    "attestation_strength": "medium"
  },
  "limitations": [
    "Witnesses attest to the encrypted commitment, not the decrypted content.",
    "The MVP does not eliminate collusion.",
    "The MVP does not provide legal admissibility certification."
  ]
}
```

## Timestamp semantics

The protocol uses the following timestamp types:

- `capture_timestamp` — device-reported time of live capture. Set by the owner device.
- `witness_timestamp` — device-reported time of witness attestation. Set by the witness device.
- `entry_timestamp` — backend-assigned time of ledger entry creation. Set by the server upon receipt.
- `grant_timestamp` — device-reported time of key grant creation. Set by the granting device.
- `report_timestamp` — device-reported time of report submission. Set by the reporting device.
- `freeze_timestamp` — time the freeze was applied. May be set by the backend or an administrative actor.

The `entry_timestamp` is the closest to a canonical ordering timestamp because it is assigned by the backend upon receipt. However, the backend itself is only partially trusted.

Device-reported timestamps (`capture_timestamp`, `witness_timestamp`, `grant_timestamp`) are advisory. They may be manipulated by compromised or misconfigured devices.

The MVP should use a configurable skew window (5 minutes by default) to flag suspicious timestamp discrepancies between device-reported times and backend receipt times. None of these timestamps are cryptographically bound to a trusted time source in the MVP.

## Replay protection

Signed payloads should include snapshot ID, ciphertext hash, session nonce, event type, timestamp, and relevant public keys.

Reject witness attestations if:

- signature is invalid,
- session nonce does not match,
- ciphertext hash does not match,
- timestamp is outside the accepted window,
- same witness key already attested to the same snapshot.
