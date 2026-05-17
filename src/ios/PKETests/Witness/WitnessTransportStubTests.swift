// Tests for the `WitnessTransport` protocol seam (HLAM-127).
// The protocol carries no behavior; these tests verify (a) that a real Swift
// type can satisfy it (AC #3), (b) the documented edge-case semantics that
// any conformer must respect, and (c) the AC #4 / #5 transport-ID rules.

import XCTest
@testable import PKEWitness

// MARK: - Test doubles

/// Minimal stub used to prove the protocol surface is implementable and to
/// exercise the `stop()`-before-emit cancellation path. Lives in the test
/// target so it never ships in the production module.
private final class NoOpTransport: WitnessTransport, @unchecked Sendable {
    let transportID: String

    private var capturerContinuation: AsyncStream<WitnessAttestation>.Continuation?
    private var witnessTask: Task<Void, Error>?

    init(transportID: String = "noop") {
        self.transportID = transportID
    }

    func runCapturer(session: WitnessSession) -> AsyncStream<WitnessAttestation> {
        AsyncStream { continuation in
            self.capturerContinuation = continuation
            continuation.onTermination = { _ in }
        }
    }

    func runWitness(
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {
        // Blocks until stop() is called (or the surrounding Task is cancelled).
        try await withTaskCancellationHandler {
            try await Task.sleep(nanoseconds: .max)
        } onCancel: { }
    }

    func stop() async {
        capturerContinuation?.finish()
        capturerContinuation = nil
        witnessTask?.cancel()
    }
}

/// Stub that invokes `sign` exactly once and propagates its result/error.
/// Used to verify the `runWitness` sign-throws contract (edge case #2).
private final class OneShotWitnessTransport: WitnessTransport, @unchecked Sendable {
    let transportID = "oneshot"
    private let session: WitnessSession

    init(session: WitnessSession) {
        self.session = session
    }

    func runCapturer(session: WitnessSession) -> AsyncStream<WitnessAttestation> {
        AsyncStream { $0.finish() }
    }

    func runWitness(
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {
        _ = try await sign(session)
    }

    func stop() async {}
}

private enum StubError: Error, Equatable {
    case boom
}

private func makeSession() -> WitnessSession {
    WitnessSession(
        sessionNonce: SessionNonce(rawValue: Data([0x01, 0x02, 0x03])),
        commitment: SnapshotCommitment(rawValue: Data([0xAA, 0xBB]))
    )
}

// MARK: - Tests

final class WitnessTransportStubTests: XCTestCase {

    // MARK: AC #3 — a stub conforming type compiles and satisfies the protocol

    func test_stubConformsToWitnessTransport() {
        let transport: any WitnessTransport = NoOpTransport()
        XCTAssertEqual(transport.transportID, "noop")
    }

    // MARK: AC #4 — transportID is a stable string per transport

    func test_transportID_isStableAcrossReads() {
        let transport = NoOpTransport(transportID: "mpc")
        XCTAssertEqual(transport.transportID, "mpc")
        XCTAssertEqual(transport.transportID, "mpc")
        XCTAssertFalse(transport.transportID.isEmpty)
    }

    // MARK: Edge case #3 — two transports with the same ID are distinct by identity

    func test_twoTransportsWithSameID_areDistinctByIdentity() {
        let first = NoOpTransport(transportID: "ble")
        let second = NoOpTransport(transportID: "ble")
        XCTAssertEqual(first.transportID, second.transportID)
        XCTAssertNotEqual(ObjectIdentifier(first), ObjectIdentifier(second))
    }

    // MARK: Edge case #1 — stop() before emit finishes the stream cleanly with zero values

    func test_runCapturer_streamFinishesCleanlyWhenStopCalledBeforeEmit() async {
        let transport = NoOpTransport()
        let stream = transport.runCapturer(session: makeSession())
        await transport.stop()

        var collected: [WitnessAttestation] = []
        for await attestation in stream {
            collected.append(attestation)
        }
        XCTAssertTrue(collected.isEmpty)
    }

    // MARK: Edge case #2 — runWitness propagates sign-closure errors

    func test_runWitness_propagatesSignClosureError() async {
        let session = makeSession()
        let transport = OneShotWitnessTransport(session: session)

        do {
            try await transport.runWitness { _ in throw StubError.boom }
            XCTFail("expected sign-closure error to propagate")
        } catch let error as StubError {
            XCTAssertEqual(error, .boom)
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    // MARK: WitnessSession value semantics

    func test_witnessSession_storesSessionNonceAndCommitment() {
        let nonce = SessionNonce(rawValue: Data([0xDE, 0xAD]))
        let commitment = SnapshotCommitment(rawValue: Data([0xBE, 0xEF]))
        let session = WitnessSession(sessionNonce: nonce, commitment: commitment)
        XCTAssertEqual(session.sessionNonce, nonce)
        XCTAssertEqual(session.commitment, commitment)
    }
}
