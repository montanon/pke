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

The snapshot bundle is encrypted locally before upload. Plaintext bundles must not be stored in the backend or committed to the public repository.

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
  "wrapping_algorithm": "example_hybrid_encryption_scheme",
  "grant_status": "active",
  "created_at": "2026-05-15T00:01:00Z",
  "grant_signature": "grant_test_signature_001"
}
```

## Data minimization

Do not include exact GPS coordinates, real names, real emails, real media, real biometrics, device serial numbers, IP addresses, private infrastructure identifiers, or production credentials.
