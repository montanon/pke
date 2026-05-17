// Tests for `WitnessSessionMachine` (HLAM-110). Covers the eight ACs +
// every documented edge case. The spy transport captures the sign
// closure on first `runWitness` invocation so each test drives requests
// into the state machine deterministically.

import XCTest
@testable import PKEWitness

// MARK: - Test doubles

/// Spy transport that records `runWitness` invocations, exposes the
/// captured sign closure for manual delivery, and counts `stop()` calls.
private final class SpyTransport: WitnessTransport, @unchecked Sendable {
    let transportID = "spy"

    private let lock = NSLock()
    private var _runWitnessCount = 0
    private var _stopCount = 0
    private var _signClosure: (@Sendable (WitnessSession) async throws -> WitnessAttestation)?
    private var awaitingRunWitness: CheckedContinuation<Void, Never>?

    var runWitnessCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _runWitnessCount
    }

    var stopCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _stopCount
    }

    func runCapturer(session: WitnessSession) -> AsyncStream<WitnessAttestation> {
        AsyncStream { $0.finish() }
    }

    func runWitness(
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {
        lock.lock()
        _runWitnessCount += 1
        _signClosure = sign
        lock.unlock()
        // Suspend until `stop()` cancels us, mimicking how a real
        // transport keeps the listener resident.
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            awaitingRunWitness = continuation
            lock.unlock()
        }
    }

    func stop() async {
        lock.lock()
        _stopCount += 1
        let continuation = awaitingRunWitness
        awaitingRunWitness = nil
        lock.unlock()
        continuation?.resume()
    }

    /// Deliver an inbound `WitnessSession` to the captured sign closure.
    /// Returns the closure's eventual result (success or error).
    func deliver(_ session: WitnessSession) async -> Result<WitnessAttestation, Error> {
        var attempts = 0
        while true {
            lock.lock()
            let captured = _signClosure
            lock.unlock()
            if let closure = captured {
                do {
                    return .success(try await closure(session))
                } catch {
                    return .failure(error)
                }
            }
            attempts += 1
            if attempts > 200 {
                return .failure(NSError(domain: "SpyTransport", code: -1))
            }
            try? await Task.sleep(nanoseconds: 10_000_000) // 10ms
        }
    }
}

// MARK: - Helpers

private func makeSession(sessionNonce nonceByte: UInt8 = 0x01) -> WitnessSession {
    WitnessSession(
        sessionNonce: SessionNonce(rawValue: Data([nonceByte])),
        commitment: SnapshotCommitment(rawValue: Data([0xAA, 0xBB]))
    )
}

private let okVerifier: @Sendable (WitnessSessionMachine.IncomingRequest) async throws -> Void
    = { _ in }

private let throwingVerifier: @Sendable (WitnessSessionMachine.IncomingRequest) async throws -> Void
    = { _ in throw VerifierError.signatureMismatch }

private enum VerifierError: Error { case signatureMismatch }

private let stubAttestation = WitnessAttestation(rawValue: Data([0x99]))

private let okSigner: @Sendable (WitnessSessionMachine.IncomingRequest) async throws -> WitnessAttestation
    = { _ in stubAttestation }

private let throwingSigner: @Sendable (WitnessSessionMachine.IncomingRequest) async throws -> WitnessAttestation
    = { _ in throw SignerError.failed }

private enum SignerError: Error { case failed }

private func makeMachine(
    transport: any WitnessTransport,
    verifier: @escaping WitnessSessionMachine.Verifier = okVerifier,
    signer: @escaping WitnessSessionMachine.Signer = okSigner,
    reviewTimeout: TimeInterval = 30,
    cacheCapacity: Int = 64
) -> WitnessSessionMachine {
    WitnessSessionMachine(
        transport: transport,
        verifier: verifier,
        signer: signer,
        reviewTimeout: reviewTimeout,
        cacheCapacity: cacheCapacity
    )
}

// MARK: - Tests

final class WitnessSessionMachineTests: XCTestCase {

    // MARK: AC #1 — startListening transitions to .available and subscribes

    func test_startListening_transitionsToAvailable_andSubscribesTransport() async throws {
        let transport = SpyTransport()
        let machine = makeMachine(transport: transport)

        await machine.startListening()
        // Allow the listener task to enter runWitness.
        try await Task.sleep(nanoseconds: 50_000_000)

        let state = await machine.currentState
        XCTAssertEqual(state, .available)
        XCTAssertEqual(transport.runWitnessCount, 1)
    }

    func test_startListening_isIdempotent() async throws {
        let transport = SpyTransport()
        let machine = makeMachine(transport: transport)

        await machine.startListening()
        await machine.startListening()
        try await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(transport.runWitnessCount, 1)
    }

    // MARK: AC #2 — receivingCommitment → verifying transitions

    func test_inboundRequest_transitionsThroughReceivingAndVerifying() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()

        let machine = makeMachine(
            transport: transport,
            verifier: { _ in
                // Keep the verifier slow enough for both states to be
                // captured before .userReview.
                try? await Task.sleep(nanoseconds: 30_000_000)
            }
        )
        await observed.attach(to: machine)
        await machine.startListening()

        let deliveryTask = Task { await transport.deliver(makeSession()) }
        // Wait until we reach .userReview, then approve.
        try await waitForState(.userReview, observed: observed)
        await machine.approve()
        _ = await deliveryTask.value

        let states = await observed.snapshot()
        XCTAssertTrue(
            stateSequenceContains(states, [.receivingCommitment, .verifying]),
            "expected receivingCommitment → verifying in transition log: \(states)"
        )
    }

    // MARK: AC #3 — verify passes → .userReview surfaces commitment

    func test_verifyPasses_transitionsToUserReview_andSurfacesCommitment() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()
        let machine = makeMachine(transport: transport)
        await observed.attach(to: machine)
        await machine.startListening()

        let session = makeSession()
        let deliveryTask = Task { await transport.deliver(session) }
        try await waitForState(.userReview, observed: observed)

        let state = await machine.currentState
        if case let .userReview(incoming) = state {
            XCTAssertEqual(incoming.sessionNonce, session.sessionNonce)
            XCTAssertEqual(incoming.commitment, session.commitment)
        } else {
            XCTFail("expected .userReview, got \(state)")
        }

        await machine.approve()
        _ = await deliveryTask.value
    }

    // MARK: AC #3 / edge-case — verifier throws

    func test_verifyThrows_transitionsToFailedAndPropagatesError() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()
        let machine = makeMachine(transport: transport, verifier: throwingVerifier)
        await observed.attach(to: machine)
        await machine.startListening()

        let result = await transport.deliver(makeSession())
        switch result {
        case .success:
            XCTFail("expected verifier-throws path to surface as error")
        case .failure(let error):
            guard case let WitnessSessionMachine.Failure.verifierThrew(reason) = error else {
                XCTFail("expected .verifierThrew, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("signatureMismatch"))
        }

        try await waitForState(
            matching: { if case .failed(.verifierThrew) = $0 { return true } else { return false } },
            in: observed,
            label: ".failed(.verifierThrew)"
        )
        let finalState = await machine.currentState
        XCTAssertEqual(finalState, .available)
    }

    // MARK: AC #4 — approve → signing → returned

    func test_userApproves_transitionsThroughSigningToReturned() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()
        let machine = makeMachine(transport: transport)
        await observed.attach(to: machine)
        await machine.startListening()

        let deliveryTask = Task { await transport.deliver(makeSession()) }
        try await waitForState(.userReview, observed: observed)
        await machine.approve()
        let result = await deliveryTask.value

        switch result {
        case .success(let attestation):
            XCTAssertEqual(attestation, stubAttestation)
        case .failure(let error):
            XCTFail("expected success, got \(error)")
        }

        try await waitForState(
            matching: { $0 == .returned },
            in: observed,
            label: ".returned"
        )
        let states = await observed.snapshot()
        XCTAssertTrue(
            stateSequenceContains(states, [.signing, .returned]),
            "expected signing → returned in transition log: \(states)"
        )
        let finalState = await machine.currentState
        XCTAssertEqual(finalState, .available)
    }

    // MARK: AC #5 — decline → declined; decline propagates

    func test_userDeclines_transitionsToDeclinedAndSendsDecline() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()
        let signerInvoked = AtomicFlag()
        let machine = makeMachine(
            transport: transport,
            signer: { _ in signerInvoked.set(); return stubAttestation }
        )
        await observed.attach(to: machine)
        await machine.startListening()

        let deliveryTask = Task { await transport.deliver(makeSession()) }
        try await waitForState(.userReview, observed: observed)
        await machine.decline()
        let result = await deliveryTask.value

        guard case .failure(let error) = result,
              case WitnessSessionMachine.Failure.declined = error else {
            XCTFail("expected .declined failure, got \(result)")
            return
        }
        XCTAssertFalse(signerInvoked.isSet)
        try await waitForState(
            matching: { $0 == .declined },
            in: observed,
            label: ".declined"
        )
        let finalState = await machine.currentState
        XCTAssertEqual(finalState, .available)
    }

    // MARK: AC #6 — replayed nonce → failed(.duplicateNonce); not sent

    func test_replayedNonce_transitionsToFailedDuplicateNonceAndDoesNotSend() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()
        let signerInvocations = AtomicCounter()
        let machine = makeMachine(
            transport: transport,
            signer: { _ in signerInvocations.increment(); return stubAttestation }
        )
        await observed.attach(to: machine)
        await machine.startListening()

        // First delivery — approve so the nonce is cached.
        let firstSession = makeSession(sessionNonce: 0x42)
        let firstTask = Task { await transport.deliver(firstSession) }
        try await waitForState(.userReview, observed: observed)
        await machine.approve()
        _ = await firstTask.value

        // Second delivery with the same sessionNonce → replay.
        let replaySession = makeSession(sessionNonce: 0x42)
        let replayResult = await transport.deliver(replaySession)
        guard case .failure(let error) = replayResult,
              case WitnessSessionMachine.Failure.duplicateNonce = error else {
            XCTFail("expected .duplicateNonce failure, got \(replayResult)")
            return
        }
        XCTAssertEqual(signerInvocations.value, 1, "signer must not run for the replay")
        try await waitForState(
            matching: { if case .failed(.duplicateNonce) = $0 { return true } else { return false } },
            in: observed,
            label: ".failed(.duplicateNonce)"
        )
    }

    // MARK: AC #8 — backgrounding → .idle, stops transport

    func test_backgrounding_transitionsToIdleAndStopsTransport() async throws {
        let transport = SpyTransport()
        let machine = makeMachine(transport: transport)
        await machine.startListening()
        try await Task.sleep(nanoseconds: 50_000_000)

        await machine.goToBackground()
        let stateAfterBg = await machine.currentState
        XCTAssertEqual(stateAfterBg, .idle)
        XCTAssertEqual(transport.stopCount, 1)
    }

    func test_backgrounding_duringUserReview_resumesAsDecline() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()
        let machine = makeMachine(transport: transport)
        await observed.attach(to: machine)
        await machine.startListening()

        let deliveryTask = Task { await transport.deliver(makeSession()) }
        try await waitForState(.userReview, observed: observed)

        await machine.goToBackground()
        let result = await deliveryTask.value
        guard case .failure(let error) = result,
              case WitnessSessionMachine.Failure.declined = error else {
            XCTFail("expected .declined on goToBackground, got \(result)")
            return
        }
        let stateAfter = await machine.currentState
        XCTAssertEqual(stateAfter, .idle)
    }

    // MARK: Review timeout → auto-decline, returns to available

    func test_reviewTimeout_autoDeclines_andReturnsToAvailable() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()
        let signerInvocations = AtomicCounter()
        let machine = makeMachine(
            transport: transport,
            signer: { _ in signerInvocations.increment(); return stubAttestation },
            reviewTimeout: 0.05
        )
        await observed.attach(to: machine)
        await machine.startListening()

        let result = await transport.deliver(makeSession())
        guard case .failure(let error) = result,
              case WitnessSessionMachine.Failure.reviewTimeout = error else {
            XCTFail("expected .reviewTimeout, got \(result)")
            return
        }
        XCTAssertEqual(signerInvocations.value, 0)
        try await waitForState(
            matching: { if case .failed(.reviewTimeout) = $0 { return true } else { return false } },
            in: observed,
            label: ".failed(.reviewTimeout)"
        )
        let finalState = await machine.currentState
        XCTAssertEqual(finalState, .available)
    }

    // MARK: observeState — initial yield + transitions

    func test_observeState_yieldsCurrentStateOnSubscribe_andSubsequentTransitions() async throws {
        let transport = SpyTransport()
        let machine = makeMachine(transport: transport)
        let observed = ObservedStates()
        await observed.attach(to: machine)
        // First yield must be .idle.
        try await Task.sleep(nanoseconds: 20_000_000)
        let initial = await observed.snapshot()
        XCTAssertEqual(initial.first, .idle)

        await machine.startListening()
        try await Task.sleep(nanoseconds: 30_000_000)
        let afterStart = await observed.snapshot()
        XCTAssertTrue(afterStart.contains(.available))
    }

    // MARK: No-op edges

    func test_approveWithoutRequest_isNoop() async {
        let transport = SpyTransport()
        let machine = makeMachine(transport: transport)
        await machine.startListening()
        await machine.approve()
        let state = await machine.currentState
        XCTAssertEqual(state, .available)
    }

    func test_declineWithoutRequest_isNoop() async {
        let transport = SpyTransport()
        let machine = makeMachine(transport: transport)
        await machine.startListening()
        await machine.decline()
        let state = await machine.currentState
        XCTAssertEqual(state, .available)
    }

    func test_backgroundFromIdle_isNoop() async {
        let transport = SpyTransport()
        let machine = makeMachine(transport: transport)
        await machine.goToBackground()
        let state = await machine.currentState
        XCTAssertEqual(state, .idle)
        XCTAssertEqual(transport.stopCount, 0)
    }

    // MARK: Signer-throws path

    func test_signerThrows_transitionsToFailedSignatureInvalid() async throws {
        let transport = SpyTransport()
        let observed = ObservedStates()
        let machine = makeMachine(
            transport: transport,
            signer: throwingSigner
        )
        await observed.attach(to: machine)
        await machine.startListening()

        let deliveryTask = Task { await transport.deliver(makeSession()) }
        try await waitForState(.userReview, observed: observed)
        await machine.approve()
        let result = await deliveryTask.value

        guard case .failure(let error) = result,
              case WitnessSessionMachine.Failure.signatureInvalid = error else {
            XCTFail("expected .signatureInvalid, got \(result)")
            return
        }
        try await waitForState(
            matching: { $0 == .failed(.signatureInvalid) },
            in: observed,
            label: ".failed(.signatureInvalid)"
        )
        let finalState = await machine.currentState
        XCTAssertEqual(finalState, .available)
    }
}

// MARK: - Observer helper

private actor ObservedStates {
    private var states: [WitnessSessionMachine.State] = []
    private var collectorTask: Task<Void, Never>?

    func attach(to machine: WitnessSessionMachine) async {
        let stream = await machine.observeState()
        collectorTask = Task {
            for await state in stream {
                await self.append(state)
            }
        }
        // Yield to let the first state arrive.
        await Task.yield()
    }

    func append(_ state: WitnessSessionMachine.State) {
        states.append(state)
    }

    func snapshot() -> [WitnessSessionMachine.State] {
        states
    }
}

/// Tag used by `waitForState` to match a top-level case without dragging
/// associated values into Equatable comparisons.
private enum StateTag {
    case userReview
}

private func waitForState(
    _ tag: StateTag,
    observed: ObservedStates,
    timeoutNanos: UInt64 = 1_000_000_000
) async throws {
    let deadline = ContinuousClock.now.advanced(by: .nanoseconds(Int64(timeoutNanos)))
    while ContinuousClock.now < deadline {
        let states = await observed.snapshot()
        for state in states {
            switch (tag, state) {
            case (.userReview, .userReview):
                return
            default:
                continue
            }
        }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTFail("timed out waiting for state \(tag); observed: \(await observed.snapshot())")
}

/// Polls the observer until one of its yielded states matches
/// `predicate`. Necessary because the observer's `for await` consumer
/// runs on a different Task than the actor's `yield(_:)` call, so a
/// synchronous snapshot taken immediately after `await deliveryTask.value`
/// can miss the post-decision transitions.
private func waitForState(
    matching predicate: @Sendable @escaping (WitnessSessionMachine.State) -> Bool,
    in observed: ObservedStates,
    timeoutNanos: UInt64 = 1_000_000_000,
    label: String
) async throws {
    let deadline = ContinuousClock.now.advanced(by: .nanoseconds(Int64(timeoutNanos)))
    while ContinuousClock.now < deadline {
        let states = await observed.snapshot()
        if states.contains(where: predicate) { return }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTFail("timed out waiting for \(label); observed: \(await observed.snapshot())")
}

private func stateSequenceContains(
    _ states: [WitnessSessionMachine.State],
    _ needle: [WitnessSessionMachine.State]
) -> Bool {
    guard !needle.isEmpty, states.count >= needle.count else { return false }
    for start in 0...(states.count - needle.count) {
        var match = true
        for offset in 0..<needle.count where states[start + offset] != needle[offset] {
            match = false
            break
        }
        if match { return true }
    }
    return false
}

// MARK: - Tiny concurrent helpers

private final class AtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = false
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return _value }
    func set() { lock.lock(); _value = true; lock.unlock() }
}

private final class AtomicCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return _value }
    func increment() { lock.lock(); _value += 1; lock.unlock() }
}
