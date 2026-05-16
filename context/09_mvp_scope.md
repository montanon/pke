# MVP Scope

## Objective

Build a native iOS prototype that demonstrates:

> live capture → local encryption → hash commitment → device signature → nearby witness attestation → append-only ledger → selective key grant → local decryption → verification report

## Must implement

### Native iOS app

Runs on real iPhones. Developer Mode installation is acceptable for the hackathon.

### Device identity

Generates local signing and encryption/key-agreement identities. Stores private keys locally and exposes public keys.

### Live photo capture

Captures a new photo inside the app. Does not import from camera roll or arbitrary files.

### Local encryption

Creates a snapshot bundle, generates a per-snapshot key, encrypts locally, computes ciphertext hash, and avoids sending plaintext to the backend.

### Owner signature

Creates and signs a snapshot commitment.

### Nearby witness attestation

Allows another nearby iPhone to receive and sign a commitment without seeing the content.

### Custody ledger

Stores custody events in an append-only hash-chained event log.

### Selective disclosure

Allows owner to grant one authorized recipient access by wrapping the snapshot key.

### Verification report

Verifies ciphertext hash, owner signature, witness signatures, ledger hash chain where feasible, and recipient key grant.

## Should include

- public-safe example schemas,
- basic report/freeze metadata action,
- simple public identity exchange,
- limitation language in UI or README,
- no sensitive media in repository.

## Explicitly not MVP

- legal-grade certification,
- objective truth verification,
- full blockchain consensus,
- proof of work,
- proof of stake,
- token economics,
- robust Sybil resistance,
- full decentralized identity,
- full social network,
- public media feed,
- arbitrary encrypted file storage,
- camera roll import,
- bulk uploads,
- production trust-and-safety operations,
- guaranteed witness independence,
- guaranteed GPS authenticity.

## MVP success criteria

The prototype succeeds if:

1. iPhone A captures a live snapshot.
2. Snapshot is encrypted locally.
3. Hash commitment is signed.
4. iPhone B signs a witness attestation without seeing content.
5. Backend stores custody events.
6. iPhone A grants access to a recipient.
7. Recipient decrypts locally.
8. Recipient sees a verification report.
9. App clearly explains limitations.
