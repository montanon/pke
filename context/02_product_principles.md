# Product Principles

## 1. Verifiable custody, not proof of reality

The system verifies custody signals, not objective truth.

## 2. Privacy by default

Evidence content is encrypted locally before remote storage or disclosure.

## 3. Live capture only

The MVP supports live in-app capture only. It should not support arbitrary uploads, camera roll imports, file picker imports, or bulk encrypted storage.

## 4. Local cryptographic sealing

Snapshots are sealed on-device through packaging, encryption, hashing, and owner signature.

## 5. Witness attestation without content exposure

Witness devices attest to the encrypted commitment, not the decrypted content.

## 6. Selective disclosure

Only authorized recipients receive access through key grants.

## 7. Cryptographic accountability

Custody events are tied to public keys and signatures. Pseudonymity may be allowed, but custody actions should remain cryptographically accountable.

## 8. Minimal public metadata

Exact location, personal identity, recipient lists, and sensitive contextual details should not be public by default.

## 9. Abuse-aware constraints

Because the backend cannot inspect end-to-end encrypted content, the product must avoid becoming a general encrypted vault or social media system.

## 10. Client-side verification where possible

Recipients should verify hashes, signatures, ledger integrity, and key grants locally.

## 11. Explicit limitations

The app should clearly communicate limitations around collusion, spoofed location, compromised devices, malicious clients, coercion, legal admissibility, and illegal-content misuse.

## 12. Scope discipline

The MVP should prioritize:

> capture → encrypt → hash → sign → attest → store → grant → decrypt → verify
