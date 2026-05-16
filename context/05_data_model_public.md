# Public Data Model

This document defines sanitized public data models for the MVP.

All examples use fake placeholder values.

## Snapshot

```json
{
  "snapshot_id": "snap_test_001",
  "ciphertext_blob_uri": "blob://example/snap_test_001",
  "ciphertext_hash": "sha256_test_hash_001",
  "owner_signing_public_key": "owner_test_signing_public_key_001",
  "owner_encryption_public_key": "owner_test_encryption_public_key_001",
  "created_at": "2026-05-15T00:00:00Z",
  "media_type": "photo",
  "public_metadata_policy": {
    "exact_location_public": false,
    "recipient_list_public": false,
    "raw_media_public": false
  },
  "owner_signature": "owner_test_signature_001"
}
```

## Snapshot Bundle

The snapshot bundle is encrypted locally before upload using a per-snapshot symmetric key with AES-256-GCM (on iOS: CryptoKit `AES.GCM`). The encrypted bundle (ciphertext) is then hashed with SHA-256 to produce the `ciphertext_hash`. The per-snapshot key is never sent to the backend in plaintext; it is wrapped for authorized recipients via key grants.

Plaintext bundles must not be stored in the backend or committed to the public repository.

```json
{
  "type": "snapshot_bundle",
  "version": "0.1",
  "media": {
    "photo": "binary_photo_data_not_in_public_repo"
  },
  "metadata": {
    "capture_timestamp": "2026-05-15T00:00:00Z",
    "location": {
      "stored_inside_encrypted_bundle": true,
      "precision": "user_selected"
    },
    "device_context": {
      "app_version": "0.1.0"
    }
  }
}
```

## Witness Attestation

```json
{
  "attestation_id": "attestation_test_001",
  "snapshot_id": "snap_test_001",
  "ciphertext_hash": "sha256_test_hash_001",
  "session_nonce": "session_nonce_test_001",
  "witness_signing_public_key": "witness_test_signing_public_key_001",
  "witness_timestamp": "2026-05-15T00:00:30Z",
  "transport": "multipeerconnectivity",
  "witness_signature": "witness_test_signature_001"
}
```

## Ledger Entry

The `event_type` must be one of: `SNAPSHOT_COMMITTED`, `WITNESS_ATTESTED`, `KEY_GRANTED`, `REPORTED`, `FROZEN`.

The `created_at` field in data models is the persistence-layer timestamp, corresponding to `entry_timestamp` in the protocol. Other protocol-level timestamps (`capture_timestamp`, `witness_timestamp`, `grant_timestamp`, `report_timestamp`, `freeze_timestamp`) are stored inside the event payload referenced by `payload_hash`.

```json
{
  "ledger_entry_id": "ledger_entry_test_001",
  "event_type": "WITNESS_ATTESTED",
  "snapshot_id": "snap_test_001",
  "payload_hash": "sha256_payload_hash_test_001",
  "previous_entry_hash": "sha256_previous_entry_hash_test_001",
  "entry_hash": "sha256_entry_hash_test_001",
  "created_at": "2026-05-15T00:00:35Z"
}
```

## Public Identity

```json
{
  "identity_id": "identity_test_001",
  "display_name": "Example Device",
  "signing_public_key": "identity_test_signing_public_key_001",
  "encryption_public_key": "identity_test_encryption_public_key_001",
  "created_at": "2026-05-15T00:00:00Z"
}
```

## Key Grant

```json
{
  "grant_id": "grant_test_001",
  "snapshot_id": "snap_test_001",
  "recipient_encryption_public_key": "recipient_test_encryption_public_key_001",
  "wrapped_snapshot_key": "wrapped_snapshot_key_test_001",
  "wrapping_algorithm": "ecdhp256+aesgcm256",
  "granted_by_signing_public_key": "owner_test_signing_public_key_001",
  "grant_status": "active",
  "created_at": "2026-05-15T00:01:00Z",
  "grant_signature": "grant_test_signature_001"
}
```

### Wrapping algorithm guidance

The `wrapping_algorithm` field identifies the cryptographic construction used to wrap the per-snapshot key for a recipient. The MVP guidance is ECDH key agreement (P-256) to derive a shared secret, HKDF to derive a wrapping key, and AES-256-GCM to wrap the snapshot key. On iOS, this maps to CryptoKit `P256.KeyAgreement` and `AES.GCM`. The identifier `"ecdhp256+aesgcm256"` represents this construction.

## Report

A report is a metadata-level action that flags a snapshot for review. It does not require backend decryption.

```json
{
  "report_id": "report_test_001",
  "snapshot_id": "snap_test_001",
  "reason_category": "abuse_concern",
  "reported_by_signing_public_key": "reporter_test_signing_public_key_001",
  "report_status": "pending",
  "created_at": "2026-05-15T00:02:00Z",
  "report_signature": "report_test_signature_001"
}
```

The `reason_category` may be one of: `abuse_concern`, `legal_request`, `owner_request`, `other`.

## Freeze

A freeze restricts future key grants for a reported snapshot. Existing custody metadata and encrypted blobs are preserved.

```json
{
  "freeze_id": "freeze_test_001",
  "snapshot_id": "snap_test_001",
  "triggered_by": "report_test_001",
  "freeze_status": "active",
  "created_at": "2026-05-15T00:02:05Z",
  "freeze_signature": "freeze_test_signature_001"
}
```

## Data minimization

Do not include exact GPS coordinates, real names, real emails, real media, real biometrics, device serial numbers, IP addresses, private infrastructure identifiers, or production credentials.
