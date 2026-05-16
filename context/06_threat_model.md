# Threat Model

## Scope

This document describes major risks and assumptions for the MVP. The project is a prototype for verifiable chain of custody of encrypted mobile evidence. It is not a legal evidence certification system and does not prove objective truth.

## Assets

Important assets include encrypted snapshot ciphertext, plaintext snapshot before encryption, per-snapshot symmetric keys, device signing keys, device encryption keys, wrapped snapshot keys, custody ledger entries, witness attestations, recipient grants, sensitive metadata, and trust relationships.

## Trust boundaries

### Partially trusted

- iOS operating system security model
- local secure storage
- intended app binary
- standard cryptographic libraries

### Not fully trusted

- backend server
- network transport
- witness devices
- owner device claims
- location data
- timestamps from clients
- public metadata
- app users

## Threat actors

### Malicious capturer

A malicious capturer may create misleading evidence, coordinate with witnesses, spoof location, manipulate device time, use a modified client, or selectively disclose evidence.

Mitigation:

- avoid proof-of-truth claims,
- sign and log custody events,
- show limitations,
- expose attestation strength conservatively.

### Malicious witness

A witness may sign dishonestly, collude, replay an attestation, or use many identities.

Mitigation:

- session nonces,
- duplicate rejection,
- timestamp windows,
- public limitation statements,
- future reputation or organization-bound identities.

### Colluding group

A group may fabricate a misleading custody trail.

Mitigation:

- do not claim collusion resistance,
- show number of attestations separately from independence,
- label attestation strength conservatively.

### Malicious backend

The backend may alter, hide, delete, or reorder custody data.

Mitigation:

- hash ciphertext,
- sign payloads,
- hash-chain ledger entries,
- verify client-side where possible.

### Network attacker

A network attacker may intercept, delay, modify, or replay messages.

Mitigation:

- sign custody payloads,
- use TLS,
- include nonces,
- reject duplicates,
- verify hashes.

### Compromised device

A compromised device may exfiltrate keys, alter UI, fake capture flows, or capture plaintext before encryption.

Mitigation:

- acknowledge limitation,
- use secure local storage,
- avoid hardware-truth claims,
- consider future hardware-backed attestation.

### Abuse actor

A user may try to store or distribute illegal, harmful, or non-consensual content.

Mitigation:

- live capture only,
- no arbitrary uploads,
- no public feed,
- no bulk encrypted storage,
- limited sharing,
- report/freeze mechanism,
- acceptable-use boundaries.

## Attack classes

### Replay attacks

Mitigate with snapshot ID, ciphertext hash, session nonce, event type, timestamp, and duplicate rejection.

### Sybil attacks

The MVP has limited Sybil resistance. It can reject duplicate witness keys but cannot prove real-world independence.

### GPS spoofing

Location is device-reported and should not be treated as definitive proof.

### Proximity spoofing

Nearby-session claims may be relayed or manipulated. Use short windows, nonces, and clear limitation labels.

### Ledger tampering

Mitigate with payload hashes, previous-entry hashes, entry hashes, and signature verification.

### Key compromise

Private key compromise undermines identity and disclosure security. Store keys securely and consider future rotation.

## Residual risks

The MVP cannot eliminate collusion, compromised devices, malicious clients, illegal live capture, coercive disclosure, legal admissibility uncertainty, or metadata inference.

## Preferred verification language

Use:

- custody verified,
- hash verified,
- signature verified,
- witness attestations verified,
- tamper-evident,
- limitations apply.

Avoid:

- verified true,
- proved real,
- impossible to fake,
- legally certified,
- tamper-proof.
