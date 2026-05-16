# Demo Scenarios

This file contains fictional, public-safe demo scenarios.

Do not use real incidents, real people, real locations, real media, or sensitive evidence in public demo materials.

## Scenario A: Basic custody creation

1. Capturer opens the iOS app.
2. Capturer selects "Create Evidence Snapshot."
3. App captures a new photo inside the app.
4. App encrypts the snapshot locally.
5. App computes the ciphertext hash.
6. App signs the snapshot commitment.
7. Backend stores encrypted blob and custody event.
8. App displays "Snapshot committed."

Expected result:

- snapshot ID,
- ciphertext hash,
- owner signature status,
- ledger entry status,
- content remains encrypted.

## Scenario B: Nearby witness attestation

1. Capturer starts a witness session.
2. Witness opens the app on a nearby iPhone.
3. Witness receives the commitment payload.
4. Witness app signs the commitment.
5. Backend records witness attestation.
6. Capturer sees witness count update.

Expected result:

- witness public key,
- valid witness signature,
- attestation timestamp,
- transport method,
- no content disclosure to witness.

## Scenario C: Selective disclosure

1. Recipient shares public encryption key.
2. Owner selects recipient.
3. Owner creates key grant.
4. App wraps snapshot key for recipient.
5. Backend stores wrapped key.
6. Recipient opens snapshot record.
7. Recipient verifies custody report.
8. Recipient decrypts locally.

Expected result: the recipient can view the content only after receiving a valid key grant.

## Scenario D: Verification report

The report should show:

```text
Ciphertext hash: verified
Owner signature: verified
Witness signatures: verified
Ledger integrity: verified
Key grant: verified
Attestation strength: medium
```

It should also show limitations:

```text
This report verifies custody signals, not objective truth.
Witnesses attested to the encrypted commitment, not the decrypted content.
The MVP does not eliminate collusion.
```

## Scenario E: Report/freeze

1. User reports a snapshot record.
2. Backend marks snapshot as reported.
3. System freezes future key grants.
4. Verification view displays reported status.
5. Existing custody trail remains preserved.

## Avoid public demos with

- real protest footage,
- real crime footage,
- real personal disputes,
- real minors,
- real addresses,
- real workplace incidents,
- real identifiable bystanders,
- real private conversations,
- real GPS coordinates.
