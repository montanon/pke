# Security Assumptions

## Device assumptions

The MVP assumes:

- the user installs the intended app build,
- the app binary is not maliciously modified,
- iOS provides reasonable process isolation,
- secure local storage protects private keys,
- the device is not fully compromised.

If the device is compromised, a malicious actor may capture plaintext, misuse private keys, alter UI behavior, fake capture flows, or exfiltrate decrypted evidence.

## Cryptographic assumptions

The MVP assumes:

- standard primitives are used correctly,
- private keys remain private,
- randomness is secure,
- per-snapshot symmetric keys have adequate entropy,
- signatures are verified over canonical payloads,
- encryption uses authenticated encryption,
- plaintext snapshot keys are never sent to the backend.

## Backend assumptions

The backend is not trusted with plaintext evidence. It may coordinate storage, ledger entries, identity records, key grants, and reports.

The backend should not be able to decrypt evidence, forge valid signatures, modify ciphertext without detection, or silently rewrite custody history without breaking hash-chain verification.

The backend may still refuse service, delete data, hide data, reveal stored metadata, or correlate public keys and access patterns.

## Witness assumptions

A witness signature means a device key signed a commitment payload. It does not prove that the human witness understood the event, saw the content, was honest, was independent, or could not be colluding.

## Location assumptions

Location is a device-reported signal. The MVP does not assume GPS is impossible to spoof.

## Time assumptions

Device time may be manipulated. The protocol uses four timestamp types:

- `capture_timestamp` — device-reported time of live capture.
- `witness_timestamp` — device-reported time of witness attestation.
- `entry_timestamp` — backend-assigned time of ledger entry creation.
- `grant_timestamp` — device-reported time of key grant creation.

The `entry_timestamp` is the closest to a canonical ordering timestamp because it is assigned by the backend upon receipt. However, the backend itself is only partially trusted.

The MVP should use a configurable skew window (5 minutes by default) to flag suspicious discrepancies between device-reported times and backend receipt times. None of these timestamps are cryptographically bound to a trusted time source in the MVP.

## Network assumptions

Network transport may be observed, delayed, interrupted, or replayed. Use signed payloads, nonces, TLS, duplicate rejection, and timestamp windows.

## Identity assumptions

Device public keys provide cryptographic continuity, not real-world identity verification.

## Identity lifecycle assumptions

The MVP assumes the following identity lifecycle:

- Device identities are generated locally at first launch.
- A signing keypair (P-256) and an encryption/key-agreement keypair (P-256) are created.
- Private keys are stored in iOS Keychain. Future work may use Secure Enclave.
- Public keys are registered with the backend identity registry.
- The MVP does not implement key rotation or key revocation.
- If a device key is compromised, there is no mechanism to invalidate past signatures or custody events signed with that key.
- Future work may add key rotation (signing a new identity with the old key), key expiry, revocation lists, and organization-backed credentials.

## Revocation assumptions

If a recipient has already decrypted a snapshot, the system cannot force them to forget or delete it. The MVP can restrict future key grants or mark access as frozen, but cannot guarantee removal of already-disclosed plaintext.

## Legal assumptions

The MVP does not certify legal admissibility. Legal admissibility depends on jurisdiction, capture context, consent rules, chain-of-custody requirements, and evidentiary procedures.

## Abuse assumptions

The MVP cannot fully prevent misuse under pure E2EE. It relies on live capture, no arbitrary uploads, no public feed, limited sharing, cryptographic accountability, and report/freeze mechanisms.
