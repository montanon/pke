# Privacy and Abuse

## Purpose

This document describes privacy and abuse constraints for a pure end-to-end encrypted evidence prototype.

End-to-end encryption protects sensitive evidence, but it also limits the backend's ability to inspect content. The product must therefore avoid becoming a general encrypted media vault or private distribution network.

## Privacy model

The privacy model is:

- capture locally,
- encrypt locally,
- store encrypted content remotely,
- expose minimal public metadata,
- disclose content only through key grants,
- verify custody without public content exposure.

## Pure E2EE tradeoff

If the backend cannot decrypt content, it cannot reliably classify content.

The system cannot guarantee prevention of illegal content storage, non-consensual imagery, harmful private media, extortion-oriented capture, or abusive live capture.

The project must explicitly acknowledge this limitation.

## Product constraints

### Live capture only

The MVP should not support arbitrary uploads, camera roll import, file picker import, bulk uploads, or encrypted archive behavior.

### No public feed

The ledger may show custody commitments, but the app should not behave like a social media timeline.

### No general social network

Avoid followers, likes, comments, reposts, and discovery feeds. Use roles: capturer, witness, authorized recipient, verifier.

### Selective disclosure only

Evidence content should be available only to recipients with valid key grants.

### Minimal public metadata

Avoid public exposure of exact location, real names, recipient lists, sensitive descriptions, raw media, audio transcripts, bystander identity, and witness real-world identity.

### Report/freeze mechanism

A report may freeze future key grants, hide optional public metadata, mark a snapshot as reported, restrict further distribution, or preserve custody metadata for process review.

A report does not require backend decryption.

## Acceptable-use boundaries

The prototype is not intended for illegal media, non-consensual intimate imagery, stalking, doxxing, harassment, blackmail, private surveillance, covert recording in private spaces, or general encrypted file sharing.

## Audio and video

Audio and video create additional consent and privacy risks. Photo capture should be the MVP default. If audio is included, it should require explicit action, display a warning, limit duration, avoid background recording, and encrypt immediately.

## Location privacy

Exact location can endanger users and witnesses. It should not be public by default. If included, exact location should generally be stored inside the encrypted bundle.

## Public repository constraints

The public repository must not include real evidence samples, real photos, real audio, real locations, real identities, real abuse reports, private keys, or production credentials.

## Honest limitation statement

Because this prototype uses end-to-end encryption, the backend is not designed to inspect encrypted content. Abuse mitigation relies on live-capture constraints, limited distribution mechanics, cryptographic accountability, metadata-level reporting, and careful scope control.
