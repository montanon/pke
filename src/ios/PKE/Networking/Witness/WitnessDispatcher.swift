// Capturer-side orchestrator for the witness flow (HLAM-50 #2 / HLAM-128).
// Fans a `WitnessSession` out to every registered `WitnessTransport`,
// merges their per-transport `AsyncStream<WitnessAttestation>` outputs into
// a single output stream, and enforces termination on the earliest of:
//
//   * 30-second window (default; configurable for tests)
//   * 50-attestation soft cap (default; configurable for tests)
//   * explicit `stop()` call on the dispatcher
//   * downstream consumer cancellation of the output stream
//   * all transports' capturer streams finishing on their own
//
// On termination, `stop()` is invoked on each registered transport exactly
// once. Per-transport faults (a stream that finishes early without yielding)
// are absorbed silently: other transports continue. Partial sessions —
// transports that never returned a signed attestation — are dropped
// silently and do not count toward the cap.
//
// Concurrency: `WitnessDispatcher` is an `actor`; all mutable state lives
// behind its isolation. Per-dispatch state lives in a child actor
// (`DispatchSession`) so multiple in-flight `dispatch(session:)` calls have
// independent windows, counters, and termination flags.

import Foundation

public actor WitnessDispatcher {
    public typealias Transport = any WitnessTransport

    private let window: TimeInterval
    private let cap: Int
    private var transports: [Transport] = []
    private var activeSessions: [DispatchSession] = []

    public init(window: TimeInterval = 30, cap: Int = 50) {
        self.window = window
        self.cap = cap
    }

    /// Add a transport to be used on subsequent `dispatch` calls.
    /// In-flight dispatches snapshot the transport list and are unaffected.
    public func register(_ transport: Transport) {
        transports.append(transport)
    }

    /// Begin a witness window for `session`. Returns an `AsyncStream` that
    /// yields each `WitnessAttestation` as it arrives across every
    /// registered transport, finishes on the first termination condition
    /// (see file header), and invokes `stop()` once on each transport.
    public func dispatch(session: WitnessSession) async -> AsyncStream<WitnessAttestation> {
        let snapshot = transports
        let (stream, continuation) = AsyncStream<WitnessAttestation>.makeStream()

        guard !snapshot.isEmpty else {
            continuation.finish()
            return stream
        }

        let dispatchSession = DispatchSession(cap: cap, transports: snapshot, continuation: continuation)
        activeSessions.append(dispatchSession)

        continuation.onTermination = { _ in
            Task { await dispatchSession.terminate() }
        }

        await dispatchSession.start(session: session, window: window)
        return stream
    }

    /// Terminate every in-flight dispatch stream. Each terminated session
    /// invokes `stop()` once on each of its snapshot transports. Idempotent.
    /// Calling `stop()` before any `dispatch(session:)` is a no-op — there
    /// are no running transports to stop in that state.
    public func stop() async {
        let sessions = activeSessions
        activeSessions.removeAll()
        for session in sessions {
            await session.terminate()
        }
    }
}

// MARK: - Per-dispatch coordinator

/// State for one `dispatch(session:)` call. Owns the cap counter, the
/// window-timeout task, the per-transport ingest tasks, and the single
/// termination path.
private actor DispatchSession {
    private let cap: Int
    private let transports: [any WitnessTransport]
    private let continuation: AsyncStream<WitnessAttestation>.Continuation
    private var count = 0
    private var done = false
    private var pendingProducers = 0
    private var tasks: [Task<Void, Never>] = []

    init(
        cap: Int,
        transports: [any WitnessTransport],
        continuation: AsyncStream<WitnessAttestation>.Continuation
    ) {
        self.cap = cap
        self.transports = transports
        self.continuation = continuation
    }

    func start(session: WitnessSession, window: TimeInterval) {
        pendingProducers = transports.count

        let windowNanos = UInt64(max(window, 0) * 1_000_000_000)
        let windowTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: windowNanos)
            if Task.isCancelled { return }
            await self?.terminate()
        }
        tasks.append(windowTask)

        for transport in transports {
            let task = Task { [weak self] in
                let stream = transport.runCapturer(session: session)
                for await attestation in stream {
                    let accepted = (await self?.ingest(attestation)) ?? false
                    if !accepted { break }
                }
                await self?.producerFinished()
            }
            tasks.append(task)
        }
    }

    /// Returns `true` if the caller should keep pulling from its transport,
    /// `false` if the dispatcher has hit the cap (or already terminated)
    /// and the producer should bail out.
    private func ingest(_ attestation: WitnessAttestation) -> Bool {
        guard !done, count < cap else { return false }
        count += 1
        continuation.yield(attestation)
        if count >= cap {
            Task { await self.terminate() }
            return false
        }
        return true
    }

    private func producerFinished() {
        pendingProducers -= 1
        if pendingProducers <= 0 {
            Task { await self.terminate() }
        }
    }

    func terminate() async {
        guard !done else { return }
        done = true
        for task in tasks {
            task.cancel()
        }
        tasks.removeAll()
        for transport in transports {
            await transport.stop()
        }
        continuation.finish()
    }
}
