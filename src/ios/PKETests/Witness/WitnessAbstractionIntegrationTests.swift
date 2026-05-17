// End-to-end coverage that wires `WitnessDispatcher` to the shared
// `FakeWitnessTransport` (HLAM-132). Demonstrates that the public test
// double is sufficient to drive the dispatcher's window, cap, merge,
// partial-transport, and consumer-cancellation contracts without the
// bespoke `FakeCapturerTransport` that lives in `WitnessDispatcherTests`.
//
// AC coverage map for HLAM-133:
//
//   AC #1 window + hang → finish        → `test_dispatcher_withHangingFake_finishesOnWindow`
//   AC #2 two transports × 3 = 6        → `test_dispatcher_withTwoFakesEmitting3_mergesTo6`
//   AC #3 cap stops at 50               → `test_dispatcher_withFakeEmitting75_capsAt50`
//   AC #4 partial + normal              → `test_dispatcher_withPartialAndNormalFake_yieldsOnlyNormalAttestations`
//   AC #5 listener single-sign          → `WitnessListenerTests.test_sameSessionOverTwoTransports_exactlyOneSucceeds`
//   AC #6 listener invalid signature    → `WitnessListenerTests.test_verifyFailure_throwsAndProducesNoAttestation`
//   AC #7 50-task concurrent claim      → `SessionNonceTrackerTests.test_concurrentRecordSigned_samePair_isSafe`
//   AC #8 consumer cancel → stop()      → `test_dispatcher_consumerCancellation_stopsFakeTransport`
//   AC #9 AttestationStrength buckets   → `AttestationStrengthTests` (full suite)

import Foundation
import XCTest
@testable import PKEWitness

final class WitnessAbstractionIntegrationTests: XCTestCase {

    // MARK: AC #1 — hang behavior + window expiry

    func test_dispatcher_withHangingFake_finishesOnWindow() async {
        let transport = FakeWitnessTransport(behavior: .hang)
        let dispatcher = WitnessDispatcher(window: 0.1, cap: 50)
        await dispatcher.register(transport)

        let stream = await dispatcher.dispatch(session: makeSession())
        var received: [WitnessAttestation] = []
        for await attestation in stream {
            received.append(attestation)
        }
        XCTAssertTrue(received.isEmpty)
        XCTAssertEqual(transport.invocations.stopCalls, 1)
    }

    // MARK: AC #2 — two transports × 3 = 6 merged

    func test_dispatcher_withTwoFakesEmitting3_mergesTo6() async {
        let first = FakeWitnessTransport(transportID: "a", behavior: .emitN(3, delay: .zero))
        let second = FakeWitnessTransport(transportID: "b", behavior: .emitN(3, delay: .zero))
        let dispatcher = WitnessDispatcher(window: 5, cap: 50)
        await dispatcher.register(first)
        await dispatcher.register(second)

        let stream = await dispatcher.dispatch(session: makeSession())
        var received: [WitnessAttestation] = []
        for await attestation in stream {
            received.append(attestation)
        }
        XCTAssertEqual(received.count, 6)
        XCTAssertEqual(first.invocations.stopCalls, 1)
        XCTAssertEqual(second.invocations.stopCalls, 1)
    }

    // MARK: AC #3 — one transport emitting 75 caps at 50

    func test_dispatcher_withFakeEmitting75_capsAt50() async {
        let transport = FakeWitnessTransport(behavior: .emitN(75, delay: .zero))
        let dispatcher = WitnessDispatcher(window: 5, cap: 50)
        await dispatcher.register(transport)

        let stream = await dispatcher.dispatch(session: makeSession())
        var received: [WitnessAttestation] = []
        for await attestation in stream {
            received.append(attestation)
        }
        XCTAssertEqual(received.count, 50)
        XCTAssertEqual(transport.invocations.stopCalls, 1)
    }

    // MARK: AC #4 — partial + normal: only normal's attestations observed

    func test_dispatcher_withPartialAndNormalFake_yieldsOnlyNormalAttestations() async {
        let partial = FakeWitnessTransport(
            transportID: "partial",
            behavior: .partial(.milliseconds(10))
        )
        let normal = FakeWitnessTransport(
            transportID: "normal",
            behavior: .emitN(2, delay: .zero)
        )
        let dispatcher = WitnessDispatcher(window: 0.2, cap: 50)
        await dispatcher.register(partial)
        await dispatcher.register(normal)

        let stream = await dispatcher.dispatch(session: makeSession())
        var received: [WitnessAttestation] = []
        for await attestation in stream {
            received.append(attestation)
        }
        XCTAssertEqual(received.count, 2)
        XCTAssertEqual(partial.invocations.stopCalls, 1)
        XCTAssertEqual(normal.invocations.stopCalls, 1)
    }

    // MARK: AC #8 — consumer cancellation drains the registered transport

    func test_dispatcher_consumerCancellation_stopsFakeTransport() async {
        let transport = FakeWitnessTransport(behavior: .hang)
        let dispatcher = WitnessDispatcher(window: 30, cap: 50)
        await dispatcher.register(transport)

        let stream = await dispatcher.dispatch(session: makeSession())
        let consumer = Task<Void, Never> {
            for await _ in stream { return }
        }
        await Task.yield()
        consumer.cancel()
        await consumer.value

        for _ in 0..<200 where transport.invocations.stopCalls == 0 {
            try? await Task.sleep(nanoseconds: 25_000_000)
        }
        XCTAssertEqual(transport.invocations.stopCalls, 1)
    }
}

// MARK: - Helpers

private func makeSession() -> WitnessSession {
    WitnessSession(
        sessionNonce: SessionNonce(rawValue: Data([0x01])),
        commitment: SnapshotCommitment(rawValue: Data([0xAA]))
    )
}
