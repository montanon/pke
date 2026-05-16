# Problem Statement

## Problem

Mobile phones are the default tool for recording events and potential evidence. Ordinary media workflows are optimized for convenience, not evidentiary integrity.

A person can take a photo, store it in cloud storage, send it through a messaging app, or publish it on social media. These workflows can preserve media, but they usually do not provide a clear, independently verifiable custody trail.

Common problems include:

- capture context is weak or lost,
- metadata can be stripped, edited, or mistrusted,
- media can be copied without reliable custody history,
- sensitive evidence may need to remain private before disclosure,
- recipients may not be able to verify whether media changed,
- public release may endanger witnesses, victims, or investigators.

## Why encrypted storage is not enough

Encrypted storage mostly answers:

> Who can access this file?

This project asks:

> Can the custody trail of this evidence package be verified?

The distinction matters. Storage tools preserve files. Messaging tools transmit files. This project records and verifies custody events around an encrypted evidence package.

## Design challenge

The system must balance:

1. **Privacy** — evidence content should not be publicly exposed by default.
2. **Integrity** — later changes should be detectable.
3. **Attestation** — nearby devices should be able to witness the encrypted commitment without seeing content.
4. **Safety** — the system must not become a general encrypted media vault.

## Central claim

The project does not verify reality. It verifies custody signals.

The strongest claim is:

> A specific encrypted evidence package was committed, signed, witnessed, preserved, and later disclosed under a verifiable custody trail.
