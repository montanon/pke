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

## Custody event

A discrete event in the chain of custody, such as snapshot commitment, witness attestation, or key grant.

## Custody ledger

An append-only record of custody events. The MVP uses a tamper-evident hash-chained log rather than a full blockchain.

## Device identity

A cryptographic identity generated and stored on a device.

## Evidence snapshot

A live in-app capture package encrypted locally and committed to the custody ledger.

## Hash chain

A sequence of records where each record includes the hash of the previous record.

## Key grant

A record that gives an authorized recipient access to decrypt a snapshot by storing a wrapped snapshot key.

## Nearby witness

A nearby device that receives a snapshot commitment and signs an attestation.

## Owner signature

A digital signature created by the capture device over the snapshot commitment.

## Plaintext

Unencrypted data.

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

## Witness attestation

A signed statement from a witness device indicating that it received and signed a specific encrypted commitment during a nearby session.

## Terms to avoid

Avoid: proof of truth, proof of reality, impossible to fake, legally certified, decentralized truth, anonymous vault, encrypted social network, tamper-proof.

Prefer: verifiable custody, tamper-evident, encrypted evidence, witness attestation, selective disclosure, custody report, limitations apply.
