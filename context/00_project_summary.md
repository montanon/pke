# Project Summary

## One-line summary

An iPhone-native application for creating encrypted mobile evidence snapshots with a verifiable chain of custody through device signatures, nearby witness attestations, and selective disclosure.

## Core concept

The project explores a narrow evidence primitive:

> Make the custody trail of private mobile evidence verifiable.

A user captures a live snapshot on an iPhone. The app encrypts the snapshot locally, hashes the encrypted package, signs the commitment with a device key, collects nearby witness attestations, stores custody events in a tamper-evident ledger, and allows the owner to disclose the encrypted content only to authorized recipients.

## What the system can help verify

The system is designed to help verify that:

- a specific encrypted evidence package entered the system,
- the encrypted package has not changed since commitment,
- the capturing device signed the original commitment,
- nearby witness devices signed attestations for that commitment,
- custody events are preserved in a tamper-evident ledger,
- authorized recipients can decrypt content and verify the custody trail.

## What the system does not prove

The system does not prove objective truth.

It does not prove that:

- the event happened exactly as described,
- all witnesses were honest,
- the location was impossible to spoof,
- the device was uncompromised,
- the media is legally admissible,
- collusion is impossible,
- the encrypted content is safe, legal, or non-abusive.

## Intended use

The intended use case is public-interest documentation where privacy, integrity, and controlled disclosure matter.

Potential contexts include civic observation, journalistic field documentation, human-rights documentation, institutional accountability workflows, and sensitive incident recording.

## Non-goals

The project is not a general encrypted storage service, social network, public media feed, legal certification authority, blockchain-first application, or proof-of-truth system.
