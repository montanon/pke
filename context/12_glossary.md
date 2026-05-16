# Glossary

## Authorized recipient

A person or device granted access to decrypt a snapshot through a key grant.

## Capture node

A device that creates an evidence snapshot, encrypts it, signs the commitment, and submits custody events.

## Ciphertext

Encrypted data.

## Ciphertext hash

A cryptographic hash of the encrypted snapshot package.

## Commitment

A signed statement binding a device identity to a specific encrypted snapshot hash and related metadata.

## Clock skew window

A configurable tolerance for timestamp discrepancies between device-reported times and backend receipt times. The MVP default is 5 minutes.

## Custody event

A discrete event in the chain of custody, such as snapshot commitment, witness attestation, key grant, report, or freeze.

## Custody ledger

An append-only record of custody events. The MVP uses a tamper-evident hash-chained log rather than a full blockchain.

## Device identity

A cryptographic identity generated and stored on a device.

## Event type

A label identifying the kind of custody event recorded in a ledger entry. Valid types: `SNAPSHOT_COMMITTED`, `WITNESS_ATTESTED`, `KEY_GRANTED`, `REPORTED`, `FROZEN`.

## Evidence snapshot

A live in-app capture package encrypted locally and committed to the custody ledger.

## Freeze

A metadata-level action that restricts future key grants for a reported snapshot. Existing custody metadata and encrypted blobs are preserved. Creates a `FROZEN` ledger entry.

## Hash chain

A sequence of records where each record includes the hash of the previous record.

## Identity lifecycle

The creation, rotation, and revocation of device cryptographic identities. The MVP supports creation only; rotation and revocation are future work.

## Key grant

A record that gives an authorized recipient access to decrypt a snapshot by storing a wrapped snapshot key.

## Key rotation

Replacing a device key with a new key while maintaining identity continuity. Not implemented in the MVP.

## Nearby witness

A nearby device that receives a snapshot commitment and signs an attestation.

## Owner signature

A digital signature created by the capture device over the snapshot commitment.

## Plaintext

Unencrypted data.

## Report

A metadata-level action flagging a snapshot for review without requiring backend decryption. Creates a `REPORTED` ledger entry.

## Report/freeze mechanism

A two-step process: a report flags a snapshot, and a freeze restricts further key grants. Custody metadata is preserved. Neither action requires decrypting the evidence content.

## Selective disclosure

Granting decryption capability to specific recipients without making the evidence public.

## Snapshot bundle

The structured data package created before encryption.

## Snapshot key

A randomly generated symmetric key used to encrypt one snapshot bundle.

## Tamper-evident

Unauthorized changes can be detected. This does not mean tamper-proof.

## Verification report

A human-readable summary of custody verification checks and limitations.

## Wrapping algorithm

The cryptographic scheme used to encrypt a per-snapshot symmetric key for a specific recipient. The MVP uses ECDH key agreement (P-256) with AES-256-GCM wrapping, identified as `"ecdhp256+aesgcm256"`.

## Witness attestation

A signed statement from a witness device indicating that it received and signed a specific encrypted commitment during a nearby session.

## Terms to avoid

Avoid: proof of truth, proof of reality, impossible to fake, legally certified, decentralized truth, anonymous vault, encrypted social network, tamper-proof.

Prefer: verifiable custody, tamper-evident, encrypted evidence, witness attestation, selective disclosure, custody report, report/freeze, limitations apply.
