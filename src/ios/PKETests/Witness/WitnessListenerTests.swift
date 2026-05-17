// Tests for `WitnessListener` (HLAM-129). Covers the seven ACs plus the
// four documented edge cases against in-test fake transports.
//
// The fakes capture the sign closure handed to `runWitness(sign:)` so the
// test can drive it explicitly with a chosen session and inspect the
// result — no real radio is needed.

import Foundation
import XCTest
@testable import PKEWitness

// MARK: - Test doubles

/// Fake transport that captures the sign closure on `runWitness(sign:)`
/// and suspends until `stop()` is called. The test invokes the captured
/// closure directly to drive the listener's witness pipeline.
private final class FakeListenerTransport: WitnessTransport, @unchecked Sendable {
    typealias SignClosure = @Sendable (WitnessSession) async throws -> WitnessAttestation

    let transportID: String
    private let lock = NSLock()
    private var capturedSign: SignClosure?
    private var suspension: CheckedContinuation<Void, Never>?
    private var stopCount = 0
    private var runWitnessCount = 0
    private let runWitnessShouldThrow: Bool

    init(transportID: String = "fake", runWitnessShouldThrow: Bool = false) {
        self.transportID = transportID
        self.runWitnessShouldThrow = runWitnessShouldThrow
    }

    var stops: Int {
        lock.lock()
        defer { lock.unlock() }
        return stopCount
    }

    var capturedSignClosure: SignClosure? {
        lock.lock()
        defer { lock.unlock() }
        return capturedSign
    }

    var runWitnessInvocations: Int {
        lock.lock()
        defer { lock.unlock() }
        return runWitnessCount
    }

    func runCapturer(session: WitnessSession) -> AsyncStream<WitnessAttestation> {
        AsyncStream { $0.finish() }
    }

    func runWitness(
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {
        lock.lock()
        runWitnessCount += 1
        lock.unlock()
        if runWitnessShouldThrow {
            throw StubError.runWitnessFailed
        }
        lock.lock()
        capturedSign = sign
        lock.unlock()
        await withCheckedContinuation { continuation in
            lock.lock()
            suspension = continuation
            lock.unlock()
        }
    }

    func stop() async {
        lock.lock()
        let continuation = suspension
        suspension = nil
        capturedSign = nil
        stopCount += 1
        lock.unlock()
        continuation?.resume()
    }
}

private enum StubError: Error, Equatable {
    case verifyRejected
    case runWitnessFailed
    case signerFailed
}

private func nonceBytes(_ byte: UInt8) -> SessionNonce {
    SessionNonce(rawValue: Data([byte]))
}

private func commitmentBytes(_ byte: UInt8) -> SnapshotCommitment {
    SnapshotCommitment(rawValue: Data([byte]))
}

private func makeSession(nonce: UInt8 = 0x10, commitment: UInt8 = 0xC0) -> WitnessSession {
    WitnessSession(sessionNonce: nonceBytes(nonce), commitment: commitmentBytes(commitment))
}

private let testWitnessKey = WitnessSigningKey(rawValue: Data([0xAB, 0xCD]))

private let alwaysVerifies: WitnessListener.VerifyCommitment = { _ in }
private let alwaysRejects: WitnessListener.VerifyCommitment = { _ in
    throw StubError.verifyRejected
}

private func makeAttestation(for session: WitnessSession) -> WitnessAttestation {
    WitnessAttestation(rawValue: session.sessionNonce.rawValue + session.commitment.rawValue)
}

private let happySigner: WitnessListener.SignSession = { session in
    makeAttestation(for: session)
}

/// Poll until the listener has installed its sign closure on `transport`.
/// Returns `nil` if the closure never appears within the budget.
private func waitForCapturedSign(
    on transport: FakeListenerTransport,
    timeoutNanos: UInt64 = 2_000_000_000
) async -> FakeListenerTransport.SignClosure? {
    let stepNanos: UInt64 = 5_000_000
    let steps = Int(timeoutNanos / stepNanos)
    for _ in 0..<steps {
        if let closure = transport.capturedSignClosure {
            return closure
        }
        try? await Task.sleep(nanoseconds: stepNanos)
    }
    return transport.capturedSignClosure
}

// MARK: - Tests

final class WitnessListenerTests: XCTestCase {

    private func makeListener(
        verify: @escaping WitnessListener.VerifyCommitment = alwaysVerifies,
        sign: @escaping WitnessListener.SignSession = happySigner,
        tracker: SessionNonceTracker = SessionNonceTracker()
    ) -> WitnessListener {
        WitnessListener(
            nonceTracker: tracker,
            witnessKey: testWitnessKey,
            verifyCommitment: verify,
            sign: sign
        )
    }

    // MARK: AC #1 — empty listener: start() returns; nothing runs

    func test_start_withNoTransports_returnsCleanly() async {
        let listener = makeListener()
        await listener.start()
        await listener.stop()
    }

    // MARK: AC #2 — valid commitment yields a signed attestation

    func test_validCommitment_yieldsSignedAttestation() async throws {
        let listener = makeListener()
        let transport = FakeListenerTransport()
        await listener.register(transport)
        await listener.start()

        guard let signClosure = await waitForCapturedSign(on: transport) else {
            XCTFail("listener did not invoke runWitness on the transport")
            return
        }
        let session = makeSession(nonce: 0x10, commitment: 0xC0)
        let attestation = try await signClosure(session)
        XCTAssertEqual(attestation, makeAttestation(for: session))

        await listener.stop()
    }

    // MARK: AC #3 — verify failure throws and produces no attestation

    func test_verifyFailure_throwsAndProducesNoAttestation() async throws {
        let listener = makeListener(verify: alwaysRejects)
        let transport = FakeListenerTransport()
        await listener.register(transport)
        await listener.start()

        guard let signClosure = await waitForCapturedSign(on: transport) else {
            XCTFail("listener did not invoke runWitness on the transport")
            return
        }

        do {
            _ = try await signClosure(makeSession())
            XCTFail("expected verify failure to propagate")
        } catch let error as StubError {
            XCTAssertEqual(error, .verifyRejected)
        }

        await listener.stop()
    }

    // MARK: AC #4 — single-sign rule: second claim throws alreadySigned

    func test_secondClaimForSameSessionAndKey_throwsAlreadySigned() async throws {
        let listener = makeListener()
        let transport = FakeListenerTransport()
        await listener.register(transport)
        await listener.start()

        guard let signClosure = await waitForCapturedSign(on: transport) else {
            XCTFail("listener did not invoke runWitness on the transport")
            return
        }
        let session = makeSession(nonce: 0x42)
        _ = try await signClosure(session)

        do {
            _ = try await signClosure(session)
            XCTFail("expected alreadySigned on the second invocation")
        } catch let error as WitnessListener.Failure {
            XCTAssertEqual(error, .alreadySigned)
        }

        await listener.stop()
    }

    // MARK: AC #5 — successful path records the (nonce, key) pair in the tracker

    func test_successfulPath_recordsNonceInTracker() async throws {
        let tracker = SessionNonceTracker()
        let listener = makeListener(tracker: tracker)
        let transport = FakeListenerTransport()
        await listener.register(transport)
        await listener.start()

        guard let signClosure = await waitForCapturedSign(on: transport) else {
            XCTFail("listener did not invoke runWitness on the transport")
            return
        }
        let session = makeSession(nonce: 0x77)
        _ = try await signClosure(session)

        let recorded = await tracker.hasSigned(nonce: session.sessionNonce, witnessKey: testWitnessKey)
        XCTAssertTrue(recorded)

        await listener.stop()
    }

    // MARK: AC #6 — stop() invokes stop() on every registered transport

    func test_stop_callsStopOnAllRegisteredTransports() async {
        let listener = makeListener()
        let first = FakeListenerTransport(transportID: "a")
        let second = FakeListenerTransport(transportID: "b")
        await listener.register(first)
        await listener.register(second)
        await listener.start()
        _ = await waitForCapturedSign(on: first)
        _ = await waitForCapturedSign(on: second)

        await listener.stop()
        XCTAssertEqual(first.stops, 1)
        XCTAssertEqual(second.stops, 1)
    }

    // MARK: AC #7 — declared `actor`; enforced at compile time by the `actor` keyword.

    // MARK: Edge — same commitment over two transports: exactly one succeeds

    func test_sameSessionOverTwoTransports_exactlyOneSucceeds() async {
        let listener = makeListener()
        let first = FakeListenerTransport(transportID: "mpc")
        let second = FakeListenerTransport(transportID: "ble")
        await listener.register(first)
        await listener.register(second)
        await listener.start()

        guard
            let firstClosure = await waitForCapturedSign(on: first),
            let secondClosure = await waitForCapturedSign(on: second)
        else {
            XCTFail("listener did not invoke runWitness on both transports")
            return
        }

        let session = makeSession(nonce: 0x99)

        async let firstOutcome = runClosure(firstClosure, session)
        async let secondOutcome = runClosure(secondClosure, session)
        let outcomes = [await firstOutcome, await secondOutcome]

        let successes = outcomes.filter { if case .success = $0 { return true } else { return false } }
        let failures = outcomes.filter { if case .failure = $0 { return true } else { return false } }
        XCTAssertEqual(successes.count, 1, "exactly one transport should succeed")
        XCTAssertEqual(failures.count, 1, "the other transport should hit alreadySigned")

        if case let .failure(error) = failures.first {
            XCTAssertEqual(error as? WitnessListener.Failure, .alreadySigned)
        }

        await listener.stop()
    }

    // MARK: Edge — signer error propagates to caller; nonce remains claimed

    func test_signerError_propagatesAndDoesNotUnclaimNonce() async throws {
        let tracker = SessionNonceTracker()
        let throwingSigner: WitnessListener.SignSession = { _ in
            throw StubError.signerFailed
        }
        let listener = makeListener(sign: throwingSigner, tracker: tracker)
        let transport = FakeListenerTransport()
        await listener.register(transport)
        await listener.start()

        guard let signClosure = await waitForCapturedSign(on: transport) else {
            XCTFail("listener did not invoke runWitness on the transport")
            return
        }
        let session = makeSession(nonce: 0x33)
        do {
            _ = try await signClosure(session)
            XCTFail("expected signer error to propagate")
        } catch let error as StubError {
            XCTAssertEqual(error, .signerFailed)
        }

        // The nonce was claimed before signing — the listener does not
        // un-claim on signer failure, matching the single-sign-per-device
        // intent (a flaky signer should not enable retries that look like
        // a second valid attestation later).
        let recorded = await tracker.hasSigned(nonce: session.sessionNonce, witnessKey: testWitnessKey)
        XCTAssertTrue(recorded)

        await listener.stop()
    }

    // MARK: Edge — transport's runWitness throws; other transports unaffected

    func test_runWitnessThrowingTransport_doesNotAffectPeers() async throws {
        let listener = makeListener()
        let throwing = FakeListenerTransport(transportID: "boom", runWitnessShouldThrow: true)
        let healthy = FakeListenerTransport(transportID: "ok")
        await listener.register(throwing)
        await listener.register(healthy)
        await listener.start()

        guard let healthyClosure = await waitForCapturedSign(on: healthy) else {
            XCTFail("listener did not invoke runWitness on the healthy transport")
            return
        }
        let attestation = try await healthyClosure(makeSession())
        XCTAssertFalse(attestation.rawValue.isEmpty)

        await listener.stop()
        XCTAssertEqual(healthy.stops, 1)
    }

    // MARK: Edge — start() called twice is a no-op

    func test_startCalledTwice_doesNotInvokeRunWitnessTwice() async {
        let listener = makeListener()
        let transport = FakeListenerTransport()
        await listener.register(transport)
        await listener.start()
        _ = await waitForCapturedSign(on: transport)

        await listener.start()
        // Give the second start() a chance to (incorrectly) spawn a second
        // task and reach the transport.
        try? await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(transport.runWitnessInvocations, 1)
        await listener.stop()
        XCTAssertEqual(transport.stops, 1)
    }
}

// MARK: - Helpers

/// Wraps `closure(session)` in a `Result` so two parallel `async let`
/// invocations can return either success or failure without aborting the
/// task group.
private func runClosure(
    _ closure: FakeListenerTransport.SignClosure,
    _ session: WitnessSession
) async -> Result<WitnessAttestation, any Error> {
    do {
        return .success(try await closure(session))
    } catch {
        return .failure(error)
    }
}
