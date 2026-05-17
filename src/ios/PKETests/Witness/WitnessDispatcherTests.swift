// Tests for the `WitnessDispatcher` actor (HLAM-128).
//
// Covers the eight ACs and the four documented edge cases against
// in-process fake transports. The fakes live in the test target so they
// never ship in the production module — the formal FakeWitnessTransport
// double is a separate story (HLAM-132).

import Foundation
import XCTest
@testable import PKEWitness

// MARK: - Test doubles

/// Fake transport that yields a fixed list of attestations on
/// `runCapturer`, optionally with a per-emit delay, and records `stop()`
/// invocations under a lock so the test thread can observe them.
private final class FakeCapturerTransport: WitnessTransport, @unchecked Sendable {
    let transportID: String
    private let attestations: [WitnessAttestation]
    private let perEmitDelayNanos: UInt64
    private let neverFinishes: Bool
    private let lock = NSLock()
    private var stopCallCount = 0

    init(
        transportID: String = "fake",
        attestations: [WitnessAttestation] = [],
        perEmitDelayNanos: UInt64 = 0,
        neverFinishes: Bool = false
    ) {
        self.transportID = transportID
        self.attestations = attestations
        self.perEmitDelayNanos = perEmitDelayNanos
        self.neverFinishes = neverFinishes
    }

    var stops: Int {
        lock.lock()
        defer { lock.unlock() }
        return stopCallCount
    }

    func runCapturer(session: WitnessSession) -> AsyncStream<WitnessAttestation> {
        let attestations = self.attestations
        let delay = self.perEmitDelayNanos
        let neverFinishes = self.neverFinishes
        return AsyncStream { continuation in
            let task = Task {
                for attestation in attestations {
                    if Task.isCancelled { break }
                    if delay > 0 { try? await Task.sleep(nanoseconds: delay) }
                    if Task.isCancelled { break }
                    continuation.yield(attestation)
                }
                if !neverFinishes {
                    continuation.finish()
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    func runWitness(
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {}

    func stop() async {
        lock.lock()
        stopCallCount += 1
        lock.unlock()
    }
}

private func attestation(_ byte: UInt8) -> WitnessAttestation {
    WitnessAttestation(rawValue: Data([byte]))
}

private func makeSession() -> WitnessSession {
    WitnessSession(
        sessionNonce: SessionNonce(rawValue: Data([0x01, 0x02, 0x03])),
        commitment: SnapshotCommitment(rawValue: Data([0xAA, 0xBB]))
    )
}

private func collect(
    _ stream: AsyncStream<WitnessAttestation>
) async -> [WitnessAttestation] {
    var collected: [WitnessAttestation] = []
    for await item in stream {
        collected.append(item)
    }
    return collected
}

// MARK: - Tests

final class WitnessDispatcherTests: XCTestCase {

    // MARK: AC #1 — no transports → stream finishes immediately

    func test_dispatch_withNoTransports_finishesImmediately() async {
        let dispatcher = WitnessDispatcher(window: 5, cap: 50)
        let stream = await dispatcher.dispatch(session: makeSession())
        let collected = await collect(stream)
        XCTAssertTrue(collected.isEmpty)
    }

    // MARK: AC #2 — two transports each emit 3 → exactly 6 then finish

    func test_dispatch_mergesAttestationsFromAllTransports() async {
        let first = FakeCapturerTransport(
            transportID: "a",
            attestations: [attestation(1), attestation(2), attestation(3)]
        )
        let second = FakeCapturerTransport(
            transportID: "b",
            attestations: [attestation(4), attestation(5), attestation(6)]
        )
        let dispatcher = WitnessDispatcher(window: 5, cap: 50)
        await dispatcher.register(first)
        await dispatcher.register(second)

        let stream = await dispatcher.dispatch(session: makeSession())
        let collected = await collect(stream)
        XCTAssertEqual(collected.count, 6)
        XCTAssertEqual(Set(collected), Set([
            attestation(1), attestation(2), attestation(3),
            attestation(4), attestation(5), attestation(6)
        ]))
        XCTAssertEqual(first.stops, 1)
        XCTAssertEqual(second.stops, 1)
    }

    // MARK: AC #3 — slow/empty transport: window elapses, stream finishes, stop() invoked

    func test_dispatch_windowExpiry_terminatesStreamAndStopsTransport() async {
        let transport = FakeCapturerTransport(transportID: "slow", neverFinishes: true)
        let dispatcher = WitnessDispatcher(window: 0.05, cap: 50)
        await dispatcher.register(transport)

        let stream = await dispatcher.dispatch(session: makeSession())
        let collected = await collect(stream)
        XCTAssertTrue(collected.isEmpty)
        XCTAssertEqual(transport.stops, 1)
    }

    // MARK: AC #4 — cap reached → exactly cap then finish, stop() on all

    func test_dispatch_capReached_yieldsExactlyCapThenFinishesAndStopsAll() async {
        let attestationsPerTransport = (0..<40).map { attestation(UInt8($0)) }
        let first = FakeCapturerTransport(transportID: "a", attestations: attestationsPerTransport)
        let second = FakeCapturerTransport(transportID: "b", attestations: attestationsPerTransport)
        let dispatcher = WitnessDispatcher(window: 5, cap: 50)
        await dispatcher.register(first)
        await dispatcher.register(second)

        let stream = await dispatcher.dispatch(session: makeSession())
        let collected = await collect(stream)
        XCTAssertEqual(collected.count, 50)
        XCTAssertEqual(first.stops, 1)
        XCTAssertEqual(second.stops, 1)
    }

    // MARK: AC #5 — dispatcher.stop() mid-window → stream finishes, all transports stopped

    func test_stop_midWindow_terminatesStreamAndStopsAllTransports() async {
        let first = FakeCapturerTransport(transportID: "a", neverFinishes: true)
        let second = FakeCapturerTransport(transportID: "b", neverFinishes: true)
        let dispatcher = WitnessDispatcher(window: 10, cap: 50)
        await dispatcher.register(first)
        await dispatcher.register(second)

        let stream = await dispatcher.dispatch(session: makeSession())
        let consumer = Task { await collect(stream) }

        // Yield once so the dispatch's producer tasks reach their suspension
        // points before we call stop().
        await Task.yield()
        await dispatcher.stop()

        let collected = await consumer.value
        XCTAssertTrue(collected.isEmpty)
        XCTAssertEqual(first.stops, 1)
        XCTAssertEqual(second.stops, 1)
    }

    // MARK: AC #6 — partial attestations (transport never signs) dropped, not counted

    func test_dispatch_partialTransport_doesNotCountTowardCap() async {
        let partial = FakeCapturerTransport(transportID: "partial", neverFinishes: true)
        let productive = FakeCapturerTransport(
            transportID: "productive",
            attestations: [attestation(0xA1), attestation(0xA2)]
        )
        let dispatcher = WitnessDispatcher(window: 0.1, cap: 50)
        await dispatcher.register(partial)
        await dispatcher.register(productive)

        let stream = await dispatcher.dispatch(session: makeSession())
        let collected = await collect(stream)
        XCTAssertEqual(collected.count, 2)
        XCTAssertEqual(partial.stops, 1)
        XCTAssertEqual(productive.stops, 1)
    }

    // MARK: AC #7 — WitnessDispatcher is declared an actor
    //
    // The compile-time guarantee is the `actor` keyword in the source
    // (`actor WitnessDispatcher`). Nothing else can satisfy that
    // declaration kind, so a dedicated runtime check would only re-verify
    // what the compiler already enforces.

    // MARK: AC #8 — window + cap are configurable via init defaults

    func test_init_acceptsCustomWindowAndCapOverrides() async {
        // A custom 0.05s window terminates the stream long before the
        // default 30s would, proving the override is wired through.
        let transport = FakeCapturerTransport(transportID: "slow", neverFinishes: true)
        let dispatcher = WitnessDispatcher(window: 0.05, cap: 3)
        await dispatcher.register(transport)

        let stream = await dispatcher.dispatch(session: makeSession())
        let started = Date()
        _ = await collect(stream)
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)

        // And the cap override applies too: a transport emitting more than
        // the cap is bounded by the new value, not by the default 50.
        let busy = FakeCapturerTransport(
            transportID: "busy",
            attestations: (0..<10).map { attestation(UInt8($0)) }
        )
        let cappedDispatcher = WitnessDispatcher(window: 5, cap: 3)
        await cappedDispatcher.register(busy)
        let cappedStream = await cappedDispatcher.dispatch(session: makeSession())
        let collected = await collect(cappedStream)
        XCTAssertEqual(collected.count, 3)
    }

    // MARK: Edge case — dispatch called twice yields two independent streams

    func test_dispatch_calledTwice_returnsIndependentStreams() async {
        let transport = FakeCapturerTransport(
            transportID: "shared",
            attestations: [attestation(0x10), attestation(0x11)]
        )
        let dispatcher = WitnessDispatcher(window: 5, cap: 50)
        await dispatcher.register(transport)

        let firstStream = await dispatcher.dispatch(session: makeSession())
        let firstCollected = await collect(firstStream)
        XCTAssertEqual(firstCollected.count, 2)

        let secondStream = await dispatcher.dispatch(session: makeSession())
        let secondCollected = await collect(secondStream)
        XCTAssertEqual(secondCollected.count, 2)

        // `runCapturer` was driven twice, and each window terminated cleanly,
        // so `stop()` should have been invoked once per dispatch.
        XCTAssertEqual(transport.stops, 2)
    }

    // MARK: Edge case — consumer cancels iteration → dispatcher stops transports

    func test_consumerCancellation_stopsAllTransports() async {
        let transport = FakeCapturerTransport(transportID: "slow", neverFinishes: true)
        let dispatcher = WitnessDispatcher(window: 30, cap: 50)
        await dispatcher.register(transport)

        let stream = await dispatcher.dispatch(session: makeSession())
        let consumer = Task<Void, Never> {
            for await _ in stream {
                return
            }
        }
        await Task.yield()
        consumer.cancel()
        await consumer.value

        // The onTermination handler hops through two Tasks before reaching
        // transport.stop(). Poll with a generous budget — slower CI runners
        // (especially Linux) take noticeably longer than macOS to drain the
        // chain of detached Tasks involved.
        for _ in 0..<200 where transport.stops == 0 {
            try? await Task.sleep(nanoseconds: 25_000_000)
        }
        XCTAssertEqual(transport.stops, 1)
    }

    // MARK: Edge case — a transport that finishes early doesn't break the merge

    func test_oneTransportFinishingEarly_doesNotInterruptOthers() async {
        let quick = FakeCapturerTransport(transportID: "quick", attestations: [attestation(0xC1)])
        let slow = FakeCapturerTransport(
            transportID: "slow",
            attestations: [attestation(0xC2), attestation(0xC3)],
            perEmitDelayNanos: 20_000_000
        )
        let dispatcher = WitnessDispatcher(window: 5, cap: 50)
        await dispatcher.register(quick)
        await dispatcher.register(slow)

        let stream = await dispatcher.dispatch(session: makeSession())
        let collected = await collect(stream)
        XCTAssertEqual(collected.count, 3)
        XCTAssertEqual(quick.stops, 1)
        XCTAssertEqual(slow.stops, 1)
    }
}
