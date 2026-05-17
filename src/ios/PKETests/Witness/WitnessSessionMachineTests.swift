// Tests for `WitnessSessionMachine` (HLAM-110). Covers the eight ACs +
// every documented edge case. The spy transport and helper plumbing
// live in `WitnessSessionMachineTestSupport.swift`.

import XCTest
@testable import PKEWitness

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
            },
            signer: okSigner
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
            signer: { _ in signerInvoked.set(); return stubAttestation },
            reviewTimeout: 30
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
            signer: { _ in signerInvocations.increment(); return stubAttestation },
            reviewTimeout: 30
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
