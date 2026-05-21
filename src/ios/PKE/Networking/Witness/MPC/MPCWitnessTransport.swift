// HLAM-158 — capturer-side flow of the MultipeerConnectivity witness
// transport (`MPCWitnessTransport.runCapturer`).
//
// HLAM-52 Story 1 (the `MCSession` adapter, HLAM-156) was reverted from
// the repo (PR #76), so this story does not build on it directly.
// Instead `runCapturer`'s logic is decoupled from MultipeerConnectivity
// behind the `MPCCapturerChannel` seam: the channel exposes connection /
// data events, framed sends, and a single `stop()`. The real
// `MCSession`-backed conformer (`MPCSessionCapturerChannel`) is
// `#if canImport(MultipeerConnectivity)`-gated; unit tests inject a
// no-op fake. This keeps the capturer flow testable on Linux CI.
//
// `runWitness` is HLAM-159 — shipped here as a placeholder that throws,
// purely to satisfy `WitnessTransport` conformance.

import Foundation

/// Stable identifier for one discovered peer within a capturer session.
/// Backed by the MPC peer display name, which is itself a random
/// per-session `"pke-"` string — no cross-session correlation.
public struct MPCPeerHandle: Hashable, Sendable {
    public let id: String

    public init(id: String) {
        self.id = id
    }
}

/// Events surfaced by an `MPCCapturerChannel` while advertising.
public enum MPCCapturerEvent: Sendable {
    case peerConnected(MPCPeerHandle)
    case dataReceived(peer: MPCPeerHandle, data: Data)
    case peerDisconnected(MPCPeerHandle)
}

/// Capturer-side seam over an MPC session: advertise, observe peer
/// events, send framed payloads, disconnect peers, and tear down.
/// Conformers are reference types so the transport can track active
/// channels by identity.
public protocol MPCCapturerChannel: AnyObject, Sendable {
    /// Connection / data / disconnection events for advertised peers.
    /// Finishes when `stop()` is called.
    var events: AsyncStream<MPCCapturerEvent> { get }

    /// Begin advertising the witness service under `displayName`.
    func startAdvertising(displayName: String) async

    /// Send an already-framed payload to a single connected peer.
    func send(_ data: Data, toPeer peer: MPCPeerHandle) async

    /// Drop a single peer once its attestation has been collected.
    func disconnect(_ peer: MPCPeerHandle) async

    /// Stop advertising, disconnect everyone, and finish `events`.
    func stop() async
}

public enum MPCWitnessTransportError: Error, Equatable, Sendable {
    /// `runWitness` is implemented by HLAM-159; this transport build
    /// only ships the capturer role.
    case witnessRoleNotImplemented
}

/// `MultipeerConnectivity` witness transport — foreground-primary
/// witness path. This build implements the capturer role
/// (`runCapturer`); see `MPCWitnessTransportError.witnessRoleNotImplemented`.
public actor MPCWitnessTransport: WitnessTransport {

    /// MPC service type — ≤15 chars, lowercase + hyphens per MPC rules.
    public static let serviceType = "pke-witness"

    /// `NSBonjourServices` Info.plist entries for `serviceType`.
    public static let bonjourServices = ["_pke-witness._tcp", "_pke-witness._udp"]

    /// Per-connection idle timeout (HLAM-161). A peer that has not
    /// delivered a complete attestation within this window is dropped,
    /// freeing its MPC slot for the next witness.
    public static let perConnectionIdleTimeout: TimeInterval = 5

    /// Default idle-timer sleep — wraps `Task.sleep`. Returns early
    /// (without throwing) on cancellation so the timer task can exit
    /// cleanly during teardown.
    public static let defaultSleep: @Sendable (TimeInterval) async -> Void = { seconds in
        try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
    }

    nonisolated public var transportID: String { "multipeerconnectivity" }

    private let channelFactory: @Sendable () -> any MPCCapturerChannel
    private let idleTimeout: TimeInterval
    private let sleep: @Sendable (TimeInterval) async -> Void
    private var activeChannels: [any MPCCapturerChannel] = []
    private var isStopped = false

    /// Designated initializer. `channelFactory` vends one channel per
    /// `runCapturer` call; tests inject a fake here. `idleTimeout` and
    /// `sleep` are injectable so unit tests can drive the per-connection
    /// timeout deterministically without wall-clock waits.
    public init(
        channelFactory: @escaping @Sendable () -> any MPCCapturerChannel,
        idleTimeout: TimeInterval = MPCWitnessTransport.perConnectionIdleTimeout,
        sleep: @escaping @Sendable (TimeInterval) async -> Void = MPCWitnessTransport.defaultSleep
    ) {
        self.channelFactory = channelFactory
        self.idleTimeout = idleTimeout
        self.sleep = sleep
    }

    /// One step consumed by the capturer event loop: either an event
    /// from the MPC channel or a fired per-connection idle timeout.
    private enum CapturerStep: Sendable {
        case event(MPCCapturerEvent)
        case idleTimeout(peer: MPCPeerHandle, generation: Int)
    }

    /// Mutable state for a single `runCapturer` call. Only ever touched
    /// from the transport's serial capturer loop, so it needs no
    /// synchronization and never leaves the actor's isolation domain.
    private final class CapturerContext {
        let channel: any MPCCapturerChannel
        let commitmentFrame: Data
        let steps: AsyncStream<CapturerStep>.Continuation
        let attestations: AsyncStream<WitnessAttestation>.Continuation
        var accumulators: [MPCPeerHandle: MPCFrameAccumulator] = [:]
        var timeoutGeneration: [MPCPeerHandle: Int] = [:]
        var timeoutTasks: [MPCPeerHandle: Task<Void, Never>] = [:]
        var nextGeneration = 0

        init(
            channel: any MPCCapturerChannel,
            commitmentFrame: Data,
            steps: AsyncStream<CapturerStep>.Continuation,
            attestations: AsyncStream<WitnessAttestation>.Continuation
        ) {
            self.channel = channel
            self.commitmentFrame = commitmentFrame
            self.steps = steps
            self.attestations = attestations
        }
    }

    // MARK: - WitnessTransport

    nonisolated public func runCapturer(
        session: WitnessSession
    ) -> AsyncStream<WitnessAttestation> {
        let channel = channelFactory()
        return AsyncStream { continuation in
            let task = Task {
                await self.driveCapturer(
                    session: session,
                    channel: channel,
                    continuation: continuation
                )
            }
            continuation.onTermination = { _ in
                task.cancel()
                Task { await channel.stop() }
            }
        }
    }

    public func runWitness(
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {
        _ = sign
        throw MPCWitnessTransportError.witnessRoleNotImplemented
    }

    public func stop() async {
        isStopped = true
        let channels = activeChannels
        activeChannels.removeAll()
        for channel in channels {
            await channel.stop()
        }
    }

    // MARK: - Capturer flow

    private func driveCapturer(
        session: WitnessSession,
        channel: any MPCCapturerChannel,
        continuation: AsyncStream<WitnessAttestation>.Continuation
    ) async {
        guard !isStopped else {
            await channel.stop()
            continuation.finish()
            return
        }
        activeChannels.append(channel)
        await channel.startAdvertising(displayName: Self.makeDisplayName())
        await runEventLoop(channel: channel, session: session, continuation: continuation)
        await teardown(channel: channel, continuation: continuation)
    }

    private func runEventLoop(
        channel: any MPCCapturerChannel,
        session: WitnessSession,
        continuation: AsyncStream<WitnessAttestation>.Continuation
    ) async {
        let commitmentFrame: Data
        do {
            commitmentFrame = try MPCMessageFraming.encode(session.commitment.rawValue)
        } catch {
            return
        }

        // Merge channel events and fired idle timeouts into one stream so
        // a single serial loop owns all per-peer state. The forwarder
        // finishes `steps` when the channel's own events end, which ends
        // the loop below.
        let (steps, stepContinuation) = AsyncStream<CapturerStep>.makeStream()
        let forwarder = Task {
            for await event in channel.events {
                stepContinuation.yield(.event(event))
            }
            stepContinuation.finish()
        }

        let context = CapturerContext(
            channel: channel,
            commitmentFrame: commitmentFrame,
            steps: stepContinuation,
            attestations: continuation
        )
        for await step in steps {
            await handle(step, context: context)
        }

        forwarder.cancel()
        for task in context.timeoutTasks.values {
            task.cancel()
        }
    }

    private func handle(_ step: CapturerStep, context: CapturerContext) async {
        switch step {
        case let .event(.peerConnected(peer)):
            context.accumulators[peer] = MPCFrameAccumulator()
            startIdleTimer(for: peer, context: context)
            await context.channel.send(context.commitmentFrame, toPeer: peer)
        case let .event(.dataReceived(peer, data)):
            await handleData(peer: peer, data: data, context: context)
        case let .event(.peerDisconnected(peer)):
            context.accumulators[peer] = nil
            clearIdleTimer(for: peer, context: context)
        case let .idleTimeout(peer, generation):
            await handleIdleTimeout(peer: peer, generation: generation, context: context)
        }
    }

    private func handleData(
        peer: MPCPeerHandle,
        data: Data,
        context: CapturerContext
    ) async {
        guard let accumulator = context.accumulators[peer] else { return }
        let frames = Self.drain(accumulator, appending: data)
        for frame in frames {
            context.attestations.yield(WitnessAttestation(rawValue: frame))
        }
        guard !frames.isEmpty else { return }
        context.accumulators[peer] = nil
        clearIdleTimer(for: peer, context: context)
        await context.channel.disconnect(peer)
    }

    /// Honors a fired idle timeout only if it is still the current timer
    /// for the peer and the peer has not yet completed — otherwise the
    /// fire is stale (peer already attested, disconnected, or reconnected).
    private func handleIdleTimeout(
        peer: MPCPeerHandle,
        generation: Int,
        context: CapturerContext
    ) async {
        guard context.timeoutGeneration[peer] == generation,
              context.accumulators[peer] != nil else { return }
        context.accumulators[peer] = nil
        clearIdleTimer(for: peer, context: context)
        await context.channel.disconnect(peer)
    }

    /// Starts the 5s idle timer for a freshly connected peer. The
    /// monotonic generation tags the fired timeout so a stale fire is
    /// ignored by `handleIdleTimeout`.
    private func startIdleTimer(for peer: MPCPeerHandle, context: CapturerContext) {
        let generation = context.nextGeneration
        context.nextGeneration += 1
        context.timeoutGeneration[peer] = generation
        context.timeoutTasks[peer]?.cancel()
        let steps = context.steps
        let sleep = self.sleep
        let timeout = self.idleTimeout
        context.timeoutTasks[peer] = Task {
            await sleep(timeout)
            guard !Task.isCancelled else { return }
            steps.yield(.idleTimeout(peer: peer, generation: generation))
        }
    }

    private func clearIdleTimer(for peer: MPCPeerHandle, context: CapturerContext) {
        context.timeoutTasks[peer]?.cancel()
        context.timeoutTasks[peer] = nil
        context.timeoutGeneration[peer] = nil
    }

    private func teardown(
        channel: any MPCCapturerChannel,
        continuation: AsyncStream<WitnessAttestation>.Continuation
    ) async {
        await channel.stop()
        activeChannels.removeAll { $0 === channel }
        continuation.finish()
    }

    /// Reassembles `data` into the accumulator and returns any complete
    /// frames. A poisoned accumulator (oversize declared length) yields
    /// no frames — the peer is dropped by the caller.
    private static func drain(
        _ accumulator: MPCFrameAccumulator,
        appending data: Data
    ) -> [Data] {
        do {
            return try accumulator.append(data)
        } catch {
            return []
        }
    }

    /// Random per-session display name — `"pke-"` + 8 lowercase hex
    /// digits (AC #1). Privacy-preserving: real identity travels in the
    /// signed attestation payload, not the broadcast name.
    static func makeDisplayName() -> String {
        "pke-" + UUID().uuidString.prefix(8).lowercased()
    }
}

#if canImport(MultipeerConnectivity)
extension MPCWitnessTransport {
    /// Convenience initializer wiring the real `MCSession`-backed
    /// channel. Available only where MultipeerConnectivity exists.
    public init() {
        self.init { MPCSessionCapturerChannel() }
    }
}
#endif
