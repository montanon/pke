// State-machine coordinator for the witness side of the PKE witness flow
// (HLAM-110). Wraps a single `WitnessTransport`'s witness-role pipeline with:
//
//   * a typed `State` exposed via `observeState()` for UI binding,
//   * a bounded recent-nonce replay cache (default 64 entries, FIFO),
//   * a user-review timeout (default 30s, configurable),
//   * an explicit `goToBackground()` transition.
//
// Naming note: the existing `WitnessSession` (in this same module) is the
// data envelope consumed by `WitnessTransport.runCapturer(session:)`. To
// avoid a name collision, the state-machine type is named
// `WitnessSessionMachine`; the AC table's `WitnessSession` reads are
// satisfied semantically by this type.
//
// Concurrency: actor-isolated; concurrent inbound requests (multiple
// invocations of the transport's sign closure) are serialised through an
// internal in-flight gate so they're handled strictly in order, per the
// edge-case row "Concurrent inbound requests".
//
// Replay-cache scope: bounded FIFO of `requestNonce` bytes seen in the
// current process lifetime. Distinct from `SessionNonceTracker`, which
// tracks `(sessionNonce, witnessKey)` pairs for the single-sign rule across
// listener invocations. The two layers are independent: the recent-nonce
// cache rejects same-request replays; the nonce tracker rejects re-signs
// for an already-signed nonce/key pair. The composition root wires both.

import Foundation

public actor WitnessSessionMachine {

    // MARK: - Public types

    /// Inbound witness request as understood by the state machine.
    ///
    /// The wire-level envelope (`WitnessSession`) only carries
    /// `sessionNonce + commitment`. The state machine treats the same bytes
    /// as the `requestNonce` for replay detection — for one app-process
    /// lifetime the two are equivalent. When HLAM-36 lands the full
    /// envelope, `requestNonce` becomes a separate field on the wire
    /// payload and `IncomingRequest` adopts it without changing this type.
    public struct IncomingRequest: Sendable, Equatable {
        public let sessionNonce: SessionNonce
        public let commitment: SnapshotCommitment
        public let requestNonce: Data

        public init(
            sessionNonce: SessionNonce,
            commitment: SnapshotCommitment,
            requestNonce: Data
        ) {
            self.sessionNonce = sessionNonce
            self.commitment = commitment
            self.requestNonce = requestNonce
        }
    }

    public enum FailureReason: Sendable, Equatable {
        case duplicateNonce
        case signatureInvalid
        case reviewTimeout
        case verifierThrew(reason: String)
    }

    public enum State: Sendable, Equatable {
        case idle
        case available
        case receivingCommitment
        case verifying
        case userReview(IncomingRequest)
        case signing
        case returned
        case declined
        case failed(FailureReason)
    }

    /// Errors raised from the sign closure back to the transport. The
    /// transport's contract owns the "no attestation produced" wire
    /// semantics: throwing any of these is how the state machine signals
    /// decline / replay / timeout to the capturer side.
    public enum Failure: Error, Equatable, Sendable {
        case declined
        case duplicateNonce
        case signatureInvalid
        case reviewTimeout
        case verifierThrew(reason: String)
    }

    public typealias Verifier =
        @Sendable (IncomingRequest) async throws -> Void
    public typealias Signer =
        @Sendable (IncomingRequest) async throws -> WitnessAttestation

    // MARK: - Stored state

    private let transport: any WitnessTransport
    private let verifier: Verifier
    private let signer: Signer
    private let reviewTimeout: TimeInterval

    private var state: State = .idle
    private var listenerTask: Task<Void, Never>?
    private var reviewContinuation: CheckedContinuation<Decision, Never>?
    private var reviewTimeoutTask: Task<Void, Never>?
    private var observers: [Int: AsyncStream<State>.Continuation] = [:]
    private var nextObserverID: Int = 0
    private var nonceCache: RecentNonceCache

    // Serialisation gate for concurrent sign-closure invocations.
    private var inFlight = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    private enum Decision: Sendable {
        case approve
        case decline
        case timeout
    }

    // MARK: - Init

    public init(
        transport: any WitnessTransport,
        verifier: @escaping Verifier,
        signer: @escaping Signer,
        reviewTimeout: TimeInterval = 30,
        cacheCapacity: Int = 64
    ) {
        self.transport = transport
        self.verifier = verifier
        self.signer = signer
        self.reviewTimeout = reviewTimeout
        self.nonceCache = RecentNonceCache(capacity: cacheCapacity)
    }

    // MARK: - Public surface

    public var currentState: State { state }

    /// Subscribe to state transitions. The returned stream yields the
    /// current state immediately and every subsequent transition until the
    /// caller cancels iteration (or the machine deinits).
    public func observeState() -> AsyncStream<State> {
        let (stream, continuation) = AsyncStream<State>.makeStream()
        let id = nextObserverID
        nextObserverID += 1
        observers[id] = continuation
        continuation.onTermination = { [weak self] _ in
            // Hoist the weak reference into an immutable capture so the
            // inner concurrent Task closure isn't capturing a `var self`
            // — Swift 5.9's stricter concurrency check (CI) rejects that.
            guard let machine = self else { return }
            Task { await machine.removeObserver(id) }
        }
        continuation.yield(state)
        return stream
    }

    /// Begin listening for inbound witness requests on the registered
    /// transport. Idempotent — a second call while listening is a no-op.
    public func startListening() {
        guard state == .idle else { return }
        transition(to: .available)

        let closure = makeSignClosure()
        listenerTask = Task { [transport] in
            try? await transport.runWitness(sign: closure)
        }
    }

    /// User-side approval of the current `.userReview` request.
    /// No-op if no request is awaiting review.
    public func approve() {
        resumeReview(.approve)
    }

    /// User-side decline of the current `.userReview` request.
    /// No-op if no request is awaiting review.
    public func decline() {
        resumeReview(.decline)
    }

    /// Drop to `.idle`, cancel the listener, stop the transport, and
    /// resume any awaiting review continuation as a decline.
    /// Idempotent from `.idle`.
    public func goToBackground() async {
        guard state != .idle else { return }
        listenerTask?.cancel()
        listenerTask = nil
        reviewTimeoutTask?.cancel()
        reviewTimeoutTask = nil
        // Transition to .idle BEFORE resuming the awaiter so the process
        // body's post-await checks see we're shutting down and skip the
        // terminal state transitions.
        transition(to: .idle)
        let pending = reviewContinuation
        reviewContinuation = nil
        pending?.resume(returning: .decline)
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
        inFlight = false
        await transport.stop()
    }

    // MARK: - Internal: observer fan-out

    private func transition(to newState: State) {
        state = newState
        for (_, continuation) in observers {
            continuation.yield(newState)
        }
    }

    private func removeObserver(_ id: Int) {
        observers.removeValue(forKey: id)
    }

    // MARK: - Internal: review-decision resume

    private func resumeReview(_ decision: Decision) {
        guard let continuation = reviewContinuation else { return }
        reviewContinuation = nil
        reviewTimeoutTask?.cancel()
        reviewTimeoutTask = nil
        continuation.resume(returning: decision)
    }

    // MARK: - Internal: in-flight gate

    private func acquireInFlight() async {
        if !inFlight {
            inFlight = true
            return
        }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
        }
        // On wake-up, inFlight is still true (handoff didn't clear it).
    }

    private func releaseInFlight() {
        if !waiters.isEmpty {
            let next = waiters.removeFirst()
            next.resume() // inFlight stays true across the handoff
        } else {
            inFlight = false
        }
    }

    // MARK: - Internal: sign-closure body

    private func makeSignClosure()
        -> @Sendable (WitnessSession) async throws -> WitnessAttestation {
        { [weak self] session in
            guard let self else { throw Failure.declined }
            return try await self.process(session: session)
        }
    }

    private func process(session: WitnessSession) async throws -> WitnessAttestation {
        await acquireInFlight()
        defer { releaseInFlight() }

        guard state != .idle else {
            throw Failure.declined
        }

        let incoming = IncomingRequest(
            sessionNonce: session.sessionNonce,
            commitment: session.commitment,
            requestNonce: session.sessionNonce.rawValue
        )

        transition(to: .receivingCommitment)
        transition(to: .verifying)
        try await runVerification(for: incoming)
        try recordNonceOrThrow(incoming)

        transition(to: .userReview(incoming))
        let decision = await awaitDecision()

        // `goToBackground()` may have flipped state to `.idle` while the
        // continuation was awaiting; keep `.idle` and surface a decline
        // (transport sees "no attestation produced").
        if state == .idle {
            throw Failure.declined
        }
        return try await applyDecision(decision, for: incoming)
    }

    private func runVerification(for incoming: IncomingRequest) async throws {
        do {
            try await verifier(incoming)
        } catch {
            let reason = String(describing: error)
            if state != .idle {
                transition(to: .failed(.verifierThrew(reason: reason)))
                resetToAvailableIfListening()
            }
            throw Failure.verifierThrew(reason: reason)
        }
    }

    private func recordNonceOrThrow(_ incoming: IncomingRequest) throws {
        if nonceCache.contains(incoming.requestNonce) {
            if state != .idle {
                transition(to: .failed(.duplicateNonce))
                resetToAvailableIfListening()
            }
            throw Failure.duplicateNonce
        }
        _ = nonceCache.insert(incoming.requestNonce)
    }

    private func awaitDecision() async -> Decision {
        let timeout = reviewTimeout
        return await withCheckedContinuation { continuation in
            reviewContinuation = continuation
            reviewTimeoutTask = Task { [weak self] in
                let nanos = UInt64(max(timeout, 0) * 1_000_000_000)
                try? await Task.sleep(nanoseconds: nanos)
                if Task.isCancelled { return }
                await self?.resumeReview(.timeout)
            }
        }
    }

    private func applyDecision(
        _ decision: Decision,
        for incoming: IncomingRequest
    ) async throws -> WitnessAttestation {
        switch decision {
        case .approve:
            return try await runSigning(for: incoming)
        case .decline:
            transition(to: .declined)
            resetToAvailableIfListening()
            throw Failure.declined
        case .timeout:
            transition(to: .failed(.reviewTimeout))
            resetToAvailableIfListening()
            throw Failure.reviewTimeout
        }
    }

    private func runSigning(for incoming: IncomingRequest) async throws -> WitnessAttestation {
        transition(to: .signing)
        let attestation: WitnessAttestation
        do {
            attestation = try await signer(incoming)
        } catch {
            if state != .idle {
                transition(to: .failed(.signatureInvalid))
                resetToAvailableIfListening()
            }
            throw Failure.signatureInvalid
        }
        if state != .idle {
            transition(to: .returned)
            resetToAvailableIfListening()
        }
        return attestation
    }

    private func resetToAvailableIfListening() {
        // Only reset if we're not shutting down. `goToBackground()`
        // transitions to `.idle` first; the post-await branches must keep
        // that and not flip the machine back to `.available`.
        if state != .idle {
            transition(to: .available)
        }
    }
}

// MARK: - RecentNonceCache

/// Bounded FIFO replay cache for `requestNonce` bytes. Lives inside the
/// `WitnessSessionMachine` actor; not thread-safe on its own.
struct RecentNonceCache {
    private let capacity: Int
    private var order: [Data] = []
    private var set: Set<Data> = []

    init(capacity: Int) {
        precondition(capacity > 0, "RecentNonceCache capacity must be > 0")
        self.capacity = capacity
    }

    func contains(_ nonce: Data) -> Bool {
        set.contains(nonce)
    }

    /// Returns `true` if `nonce` was newly inserted; `false` if it was
    /// already present (idempotent — a duplicate insert does NOT re-evict
    /// the oldest entry).
    @discardableResult
    mutating func insert(_ nonce: Data) -> Bool {
        guard !set.contains(nonce) else { return false }
        if order.count >= capacity {
            let evicted = order.removeFirst()
            set.remove(evicted)
        }
        order.append(nonce)
        set.insert(nonce)
        return true
    }
}
