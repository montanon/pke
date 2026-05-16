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

Device time may be manipulated. Verification reports may distinguish capture timestamp, witness timestamp, backend receipt timestamp, and ledger timestamp.

## Network assumptions

Network transport may be observed, delayed, interrupted, or replayed. Use signed payloads, nonces, TLS, duplicate rejection, and timestamp windows.

## Identity assumptions

Device public keys provide cryptographic continuity, not real-world identity verification.

## Revocation assumptions

If a recipient has already decrypted a snapshot, the system cannot force them to forget or delete it. The MVP can restrict future key grants or mark access as frozen, but cannot guarantee removal of already-disclosed plaintext.

## Legal assumptions

The MVP does not certify legal admissibility. Legal admissibility depends on jurisdiction, capture context, consent rules, chain-of-custody requirements, and evidentiary procedures.

## Abuse assumptions

The MVP cannot fully prevent misuse under pure E2EE. It relies on live capture, no arbitrary uploads, no public feed, limited sharing, cryptographic accountability, and report/freeze mechanisms.
