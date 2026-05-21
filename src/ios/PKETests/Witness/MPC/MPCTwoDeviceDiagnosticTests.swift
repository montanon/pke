// HLAM-162 — automated diagnostic companion to the MPC two-device
// integration test.
//
// The real two-device test (two iPhones discovering over the MPC radio)
// is a manual procedure documented in `two_device_test_plan.md`. This
// file is its automated companion: an in-process loopback that drives the
// real `MPCWitnessTransport.runCapturer` capturer flow against a
// simulated witness, exercising the framing + signature path on every CI
// platform. When a real two-device run fails, run this diagnostic first —
// if it passes, the fault is in the MPC radio layer (discovery /
// invitation), not the protocol layer (framing / signing).
//
// The witness side is simulated here (a P-256 sign + manual framing)
// rather than `MPCWitnessTransport.runWitness`, which is HLAM-159 and not
// yet implemented.

import Crypto
import Foundation
import PKECrypto
import XCTest
@testable import PKEWitness

final class MPCTwoDeviceDiagnosticTests: XCTestCase {

    // AC #2 / #3 — capturer frames the commitment, the simulated witness
    // signs it, and the returned attestation verifies against the witness
    // signing public key.
    func test_twoDevice_diagnostic_capturerReceivesVerifiableAttestation() async throws {
        let witnessKey = P256.Signing.PrivateKey()
        let commitment = SnapshotCommitment(rawValue: Data([0x01, 0x02, 0x03, 0x04]))
        let log = DiagnosticLog()
        let channel = LoopbackMPCCapturerChannel(witnessKey: witnessKey, log: log)
        let transport = MPCWitnessTransport { channel }

        let stream = transport.runCapturer(session: session(commitment: commitment))
        channel.connectPeer(diagPeer)
        let attestations = await collect(stream)

        XCTAssertEqual(attestations.count, 1)
        let payload = try XCTUnwrap(attestations.first).rawValue
        XCTAssertEqual(payload.count, 129, "expected 65-byte pubkey + 64-byte signature")

        let publicKeyBytes = Data(payload.prefix(65))
        let signature = Data(payload.suffix(64))
        XCTAssertEqual(publicKeyBytes, witnessKey.publicKey.x963Representation)

        let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyBytes)
        XCTAssertNoThrow(
            try Signatures.verify(signature, of: commitment.rawValue, by: publicKey)
        )
        print("[MPC-DIAG] \(log.steps.joined(separator: " -> ")) -> signature-verified")
    }

    // AC #2 / #5 — the commitment round-trips through `MPCMessageFraming`
    // intact and the attestation frame decodes cleanly. Isolates
    // framing-layer faults.
    func test_twoDevice_diagnostic_framingRoundTrips() async throws {
        let commitment = SnapshotCommitment(rawValue: Data([0xDE, 0xAD, 0xBE, 0xEF]))
        let channel = LoopbackMPCCapturerChannel(
            witnessKey: P256.Signing.PrivateKey(),
            log: DiagnosticLog()
        )
        let transport = MPCWitnessTransport { channel }

        let stream = transport.runCapturer(session: session(commitment: commitment))
        channel.connectPeer(diagPeer)
        _ = await collect(stream)

        XCTAssertEqual(channel.decodedCommitment, commitment.rawValue)
        let frame = try XCTUnwrap(channel.dispatchedFrame)
        XCTAssertEqual(try MPCMessageFraming.decode(frame).count, 129)
    }

    // AC #5 — the diagnostic emits an ordered, causal milestone log so a
    // CI failure points at the exact stage that broke.
    func test_twoDevice_diagnostic_emitsStepLog() async {
        let log = DiagnosticLog()
        let channel = LoopbackMPCCapturerChannel(
            witnessKey: P256.Signing.PrivateKey(),
            log: log
        )
        let transport = MPCWitnessTransport { channel }

        let stream = transport.runCapturer(session: session())
        channel.connectPeer(diagPeer)
        _ = await collect(stream)

        XCTAssertEqual(
            log.steps,
            ["advertising", "commitment-received", "witness-signed", "attestation-dispatched"]
        )
    }

    // AC #3 — a tampered signature fails verification. Confirms the
    // diagnostic actually exercises the verify path rather than passing
    // trivially.
    func test_twoDevice_diagnostic_tamperedSignatureFails() async throws {
        let witnessKey = P256.Signing.PrivateKey()
        let commitment = SnapshotCommitment(rawValue: Data([0x11, 0x22]))
        let channel = LoopbackMPCCapturerChannel(witnessKey: witnessKey, log: DiagnosticLog())
        let transport = MPCWitnessTransport { channel }

        let stream = transport.runCapturer(session: session(commitment: commitment))
        channel.connectPeer(diagPeer)
        let attestations = await collect(stream)

        var payload = try XCTUnwrap(attestations.first).rawValue
        // Flip a byte inside the 64-byte signature region (offset 65...).
        payload[payload.startIndex + 75] ^= 0xFF

        let publicKey = try P256.Signing.PublicKey(x963Representation: Data(payload.prefix(65)))
        let signature = Data(payload.suffix(64))
        XCTAssertThrowsError(
            try Signatures.verify(signature, of: commitment.rawValue, by: publicKey)
        )
    }
}

// MARK: - Fixtures

private let diagPeer = MPCPeerHandle(id: "pke-diag0001")

private func session(
    commitment: SnapshotCommitment = SnapshotCommitment(rawValue: Data([0xA0]))
) -> WitnessSession {
    WitnessSession(sessionNonce: SessionNonce(rawValue: Data([0x42])), commitment: commitment)
}

private func collect(_ stream: AsyncStream<WitnessAttestation>) async -> [WitnessAttestation] {
    var out: [WitnessAttestation] = []
    for await attestation in stream {
        out.append(attestation)
    }
    return out
}

// MARK: - Diagnostic log

/// Ordered, thread-safe trace of the loopback's causal milestones.
/// Printed on success and asserted on, so a CI failure names the stage.
final class DiagnosticLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String] = []

    func record(_ step: String) {
        lock.lock()
        entries.append(step)
        lock.unlock()
    }

    var steps: [String] {
        lock.lock()
        defer { lock.unlock() }
        return entries
    }
}

// MARK: - Loopback channel (simulated witness)

/// An `MPCCapturerChannel` that simulates the far device. The capturer's
/// outbound commitment frame is decoded, P-256-signed by an in-process
/// witness, re-framed, and delivered straight back as a `.dataReceived`
/// event — the whole capturer↔witness exchange minus the MPC radio.
final class LoopbackMPCCapturerChannel: MPCCapturerChannel, @unchecked Sendable {

    let events: AsyncStream<MPCCapturerEvent>

    private let continuation: AsyncStream<MPCCapturerEvent>.Continuation
    private let witnessKey: P256.Signing.PrivateKey
    private let log: DiagnosticLog
    private let lock = NSLock()
    private var decodedCommitmentValue: Data?
    private var dispatchedFrameValue: Data?

    init(witnessKey: P256.Signing.PrivateKey, log: DiagnosticLog) {
        (events, continuation) = AsyncStream<MPCCapturerEvent>.makeStream()
        self.witnessKey = witnessKey
        self.log = log
    }

    /// Test driver: deliver a peer-connected event so the capturer sends
    /// its commitment frame.
    func connectPeer(_ peer: MPCPeerHandle) {
        continuation.yield(.peerConnected(peer))
    }

    /// The commitment bytes the simulated witness decoded from the frame
    /// the capturer sent.
    var decodedCommitment: Data? {
        lock.lock()
        defer { lock.unlock() }
        return decodedCommitmentValue
    }

    /// The length-prefixed attestation frame dispatched back to the
    /// capturer.
    var dispatchedFrame: Data? {
        lock.lock()
        defer { lock.unlock() }
        return dispatchedFrameValue
    }

    // MARK: MPCCapturerChannel

    func startAdvertising(displayName: String) async {
        log.record("advertising")
    }

    func send(_ data: Data, toPeer peer: MPCPeerHandle) async {
        guard let commitment = try? MPCMessageFraming.decode(data) else {
            log.record("commitment-decode-failed")
            continuation.finish()
            return
        }
        lock.lock()
        decodedCommitmentValue = commitment
        lock.unlock()
        log.record("commitment-received")

        guard let signature = try? Signatures.sign(payload: commitment, with: witnessKey) else {
            log.record("witness-sign-failed")
            continuation.finish()
            return
        }
        log.record("witness-signed")

        var attestationPayload = Data()
        attestationPayload.append(witnessKey.publicKey.x963Representation)
        attestationPayload.append(signature)

        guard let frame = try? MPCMessageFraming.encode(attestationPayload) else {
            log.record("attestation-encode-failed")
            continuation.finish()
            return
        }
        lock.lock()
        dispatchedFrameValue = frame
        lock.unlock()

        continuation.yield(.dataReceived(peer: peer, data: frame))
        log.record("attestation-dispatched")
        continuation.finish()
    }

    func disconnect(_ peer: MPCPeerHandle) async {}

    func stop() async {
        continuation.finish()
    }
}
