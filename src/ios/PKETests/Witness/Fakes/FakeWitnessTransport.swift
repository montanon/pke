// `FakeWitnessTransport` — controllable `WitnessTransport` double for the
// dispatcher / listener test suites (HLAM-50 #6 / HLAM-132).
//
// Configurable behaviors:
//
//   * `.emitN(Int, delay:)` — capturer-role: yield N synthetic attestations
//      with `delay` between each, then finish the stream.
//   * `.hang` — capturer-role: never yield; finish only when `stop()` is
//      called. Useful for exercising window-timeout and cap-reached paths
//      in `WitnessDispatcher`.
//   * `.partial(Duration)` — capturer-role: simulate a peer that
//      "connected" (the runCapturer call lands in `invocations`) after the
//      given delay but never produces a signed attestation. Functionally
//      similar to `.hang` once the delay elapses; the delay is observable
//      via tests that time the elapsed window.
//   * `.signThrows` — witness-role: invoke `sign` exactly once with a
//      synthetic `WitnessSession` and discard the result without
//      dispatching anything back. Used to drive the listener's
//      sign-closure path without a real transport.
//
// Invocations are recorded behind an `NSLock` (the class is
// `@unchecked Sendable`) so tests can assert call counts after stopping
// without a separate synchronization step.
//
// The fake lives under the `PKEWitnessTests` target only. It is never
// linked into application code.

import Foundation
@testable import PKEWitness

public final class FakeWitnessTransport: WitnessTransport, @unchecked Sendable {
    public enum Behavior: Sendable {
        case emitN(Int, delay: Duration)
        case hang
        case partial(Duration)
        case signThrows
    }

    public struct Invocations: Sendable, Equatable {
        public var runCapturerCalls = 0
        public var runWitnessCalls = 0
        public var stopCalls = 0
    }

    public let transportID: String
    private let behavior: Behavior
    private let lock = NSLock()
    private var counts = Invocations()
    private var openCapturerContinuations: [AsyncStream<WitnessAttestation>.Continuation] = []
    private var witnessSuspension: CheckedContinuation<Void, Never>?
    private var isStopped = false

    public init(transportID: String = "fake", behavior: Behavior) {
        self.transportID = transportID
        self.behavior = behavior
    }

    /// Snapshot of recorded invocations. Safe to read from any thread.
    public var invocations: Invocations {
        lock.lock()
        defer { lock.unlock() }
        return counts
    }

    // MARK: - WitnessTransport

    public func runCapturer(session: WitnessSession) -> AsyncStream<WitnessAttestation> {
        lock.lock()
        counts.runCapturerCalls += 1
        let stoppedAlready = isStopped
        lock.unlock()

        return AsyncStream { continuation in
            if stoppedAlready {
                continuation.finish()
                return
            }

            lock.lock()
            openCapturerContinuations.append(continuation)
            lock.unlock()

            let behavior = self.behavior
            let task = Task { [weak self] in
                guard let self else { return }
                await self.runCapturerBehavior(behavior, into: continuation)
            }

            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    public func runWitness(
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {
        lock.lock()
        counts.runWitnessCalls += 1
        let stoppedAlready = isStopped
        lock.unlock()

        if stoppedAlready { return }

        if case .signThrows = behavior {
            let probeSession = WitnessSession(
                sessionNonce: SessionNonce(rawValue: Data([0xFE])),
                commitment: SnapshotCommitment(rawValue: Data([0xFE]))
            )
            // Invoke once and discard the result — the contract under test
            // is that the listener's sign closure runs, not that the
            // transport dispatches anything back.
            _ = try? await sign(probeSession)
        }

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if isStopped {
                lock.unlock()
                continuation.resume()
                return
            }
            witnessSuspension = continuation
            lock.unlock()
        }
    }

    public func stop() async {
        lock.lock()
        counts.stopCalls += 1
        isStopped = true
        let continuations = openCapturerContinuations
        openCapturerContinuations.removeAll()
        let witnessContinuation = witnessSuspension
        witnessSuspension = nil
        lock.unlock()

        for continuation in continuations {
            continuation.finish()
        }
        witnessContinuation?.resume()
    }

    // MARK: - Capturer behavior

    private func runCapturerBehavior(
        _ behavior: Behavior,
        into continuation: AsyncStream<WitnessAttestation>.Continuation
    ) async {
        switch behavior {
        case let .emitN(count, delay: delay):
            for index in 0..<count {
                if Task.isCancelled { return }
                if delay != .zero {
                    try? await Task.sleep(for: delay)
                    if Task.isCancelled { return }
                }
                continuation.yield(syntheticAttestation(index: index))
            }
            continuation.finish()
        case .hang:
            // Wait indefinitely; `stop()` finishes the continuation.
            return
        case let .partial(delay):
            if delay != .zero {
                try? await Task.sleep(for: delay)
            }
            // Same as `.hang` once setup completes — `stop()` is what
            // finishes the stream.
            return
        case .signThrows:
            // No capturer-side activity; close the stream immediately.
            continuation.finish()
        }
    }

    private func syntheticAttestation(index: Int) -> WitnessAttestation {
        WitnessAttestation(rawValue: Data([UInt8(truncatingIfNeeded: index)]))
    }
}
