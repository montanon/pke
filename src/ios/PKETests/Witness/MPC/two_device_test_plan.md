# MPC Two-Device Integration Test Plan

**Story:** HLAM-162 — MPC two-device integration test
**Feature:** HLAM-52 — MPC witness transport

## Purpose & scope

Verify that two physical iPhones complete one full witness attestation
exchange over the MultipeerConnectivity (MPC) transport: discovery,
commitment delivery, signing, attestation return, and signature
verification.

This manual procedure covers what cannot be exercised in CI — the MPC
radio (Bonjour advertising/browsing, peer invitation, `MCSession`
encryption). The protocol layer underneath (length-prefixed framing and
P-256 signature verification) is covered automatically by
`MPCTwoDeviceDiagnosticTests` in the `PKEWitnessTests` target, which runs
on every CI platform.

Use the automated diagnostic as the baseline: if a manual run below fails
but `MPCTwoDeviceDiagnosticTests` passes, the fault is in the MPC radio
layer, not in framing or crypto.

## Known blocker

The capturer role (`MPCWitnessTransport.runCapturer`) ships in HLAM-158.
The **witness role** (`MPCWitnessTransport.runWitness`) is **HLAM-159 and
not yet merged**. Until HLAM-159 lands, only the capturer half of this
plan is exercisable on hardware; the full two-device run and the
result-recording table below stay pending.

## Prerequisites

- Two physical iPhones, iOS 17.0 or later.
- Both devices in **Developer Mode** (Settings → Privacy & Security →
  Developer Mode), with the PKE app sideloaded via Xcode.
- Valid provisioning for both devices. Note the free-account 7-day
  provisioning expiry and the device-cap limits — re-deploy if a build
  has expired.
- Wi-Fi **and** Bluetooth enabled on both devices (MPC uses both for
  peer-to-peer transport).
- Devices within a few metres of each other, same physical space.
- Local network permission granted to the app on first launch (iOS
  prompts for it).

## Procedure

1. Launch the PKE app on both devices.
2. On **Device A**, select the **capturer** role and begin a capture so a
   snapshot commitment is produced.
3. On **Device B**, select the **witness** role so it begins browsing for
   nearby capturers.
4. Observe that the two devices discover each other (capturer advertises
   a random `pke-XXXXXXXX` display name; witness browses the
   `pke-witness` service type).
5. Confirm Device B receives the commitment, signs it, and returns the
   attestation; Device A receives the attestation.
6. On Device A, confirm the attestation's signature verifies against
   Device B's witness signing public key (verification view / console
   log).
7. Record the outcome in the table below.

## Expected results

| AC | Expectation |
|----|-------------|
| #1 | Both devices discover each other within a few seconds of entering their roles. |
| #2 | Capturer sends a length-prefixed commitment; witness signs and returns a length-prefixed attestation over the same `MCSession`. |
| #3 | The returned attestation's P-256 signature verifies against the witness signing public key. |

## Diagnostic logging checklist

A diagnostic build emits console (`os_log` / `print`) lines. Confirm each
stage; the first missing line localises the fault:

- [ ] Capturer: `startAdvertising` with a `pke-` display name → **advertising started**.
- [ ] Witness: browser found a peer → **discovery works**.
- [ ] Invitation sent and `MCSession` reaches `.connected` → **invitation / session OK**.
- [ ] Capturer: framed commitment sent (`MPCMessageFraming.encode`).
- [ ] Witness: commitment frame decoded (`MPCMessageFraming.decode`) → **framing inbound OK**.
- [ ] Witness: `sign` closure invoked, attestation produced.
- [ ] Witness: framed attestation dispatched back.
- [ ] Capturer: attestation frame reassembled and yielded.
- [ ] Signature verified against the witness public key.

Interpreting failures:

- Discovery line missing → MPC radio / Bonjour / permissions issue.
  (`MPCTwoDeviceDiagnosticTests` cannot catch this — it has no radio.)
- Framing decode line missing or `FramingError` logged → framing-layer
  fault; cross-check against `MPCTwoDeviceDiagnosticTests` and
  `MPCMessageFramingTests`.
- Verification fails → signing-key or payload-canonicalisation
  mismatch; `test_twoDevice_diagnostic_capturerReceivesVerifiableAttestation`
  is the reference for the expected payload shape (65-byte x9.63 public
  key followed by a 64-byte raw-P1363 signature).

## Result-recording table

| Date | Device A (capturer) | iOS | Device B (witness) | iOS | Outcome | Notes |
|------|---------------------|-----|--------------------|-----|---------|-------|
|      |                     |     |                    |     |         |       |
