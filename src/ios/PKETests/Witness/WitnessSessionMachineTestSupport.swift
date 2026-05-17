// Test doubles, factory helpers, and observer plumbing for
// `WitnessSessionMachineTests`. Lifted out of the main test file to keep
// it below SwiftLint's `file_length` 500-line warning threshold and to
// make the spy + observer types reusable from future witness tests.

import XCTest
@testable import PKEWitness

// MARK: - Spy transport

/// Records `runWitness` invocations, captures the supplied sign closure
/// for manual delivery by tests, and counts `stop()` calls. Cross-thread
/// safe via an internal `NSLock`.
final class SpyTransport: WitnessTransport, @unchecked Sendable {
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
        // Suspend until `stop()` resumes us, mimicking how a real
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
    /// Polls up to ~2s for the closure to be captured (covers the brief
    /// window between `runWitness` registration and the test driving it).
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

// MARK: - Test fixtures

enum VerifierError: Error { case signatureMismatch }
enum SignerError: Error { case failed }

let stubAttestation = WitnessAttestation(rawValue: Data([0x99]))

let okVerifier: @Sendable (WitnessSessionMachine.IncomingRequest) async throws -> Void
    = { _ in }

let throwingVerifier: @Sendable (WitnessSessionMachine.IncomingRequest) async throws -> Void
    = { _ in throw VerifierError.signatureMismatch }

let okSigner: @Sendable (WitnessSessionMachine.IncomingRequest) async throws -> WitnessAttestation
    = { _ in stubAttestation }

let throwingSigner: @Sendable (WitnessSessionMachine.IncomingRequest) async throws -> WitnessAttestation
    = { _ in throw SignerError.failed }

func makeSession(sessionNonce nonceByte: UInt8 = 0x01) -> WitnessSession {
    WitnessSession(
        sessionNonce: SessionNonce(rawValue: Data([nonceByte])),
        commitment: SnapshotCommitment(rawValue: Data([0xAA, 0xBB]))
    )
}

func makeMachine(
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

// MARK: - State observer

/// Collects every state yielded by `WitnessSessionMachine.observeState()`
/// into an actor-isolated buffer so tests can snapshot the transition log.
actor ObservedStates {
    private var states: [WitnessSessionMachine.State] = []
    private var collectorTask: Task<Void, Never>?

    func attach(to machine: WitnessSessionMachine) async {
        let stream = await machine.observeState()
        collectorTask = Task {
            for await state in stream {
                await self.append(state)
            }
        }
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
enum StateTag {
    case userReview
}

func waitForState(
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

/// Polls the observer until one of its yielded states matches `predicate`.
/// Necessary because the observer's `for await` consumer runs on a
/// different Task than the actor's `yield(_:)` call, so a synchronous
/// snapshot taken immediately after `await deliveryTask.value` can miss
/// the post-decision transitions.
func waitForState(
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

func stateSequenceContains(
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

final class AtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = false
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return _value }
    func set() { lock.lock(); _value = true; lock.unlock() }
}

final class AtomicCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return _value }
    func increment() { lock.lock(); _value += 1; lock.unlock() }
}
