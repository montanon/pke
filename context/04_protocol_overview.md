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
  "wrapping_algorithm": "example_hybrid_encryption_scheme",
  "granted_by_signing_public_key": "owner_test_signing_public_key_001",
  "grant_timestamp": "2026-05-15T00:01:00Z",
  "grant_signature": "grant_test_signature_001"
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

## Replay protection

Signed payloads should include snapshot ID, ciphertext hash, session nonce, event type, timestamp, and relevant public keys.

Reject witness attestations if:

- signature is invalid,
- session nonce does not match,
- ciphertext hash does not match,
- timestamp is outside the accepted window,
- same witness key already attested to the same snapshot.
