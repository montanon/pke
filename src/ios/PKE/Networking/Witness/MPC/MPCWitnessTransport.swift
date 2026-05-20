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

    /// Per-connection idle timeout (HLAM-52 Story 6 — not enforced here).
    public static let perConnectionIdleTimeout: TimeInterval = 5

    nonisolated public var transportID: String { "multipeerconnectivity" }

    private let channelFactory: @Sendable () -> any MPCCapturerChannel
    private var activeChannels: [any MPCCapturerChannel] = []
    private var isStopped = false

    /// Designated initializer. `channelFactory` vends one channel per
    /// `runCapturer` call; tests inject a fake here.
    public init(channelFactory: @escaping @Sendable () -> any MPCCapturerChannel) {
        self.channelFactory = channelFactory
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
        var accumulators: [MPCPeerHandle: MPCFrameAccumulator] = [:]
        for await event in channel.events {
            switch event {
            case let .peerConnected(peer):
                accumulators[peer] = MPCFrameAccumulator()
                await channel.send(commitmentFrame, toPeer: peer)
            case let .dataReceived(peer, data):
                guard let accumulator = accumulators[peer] else { continue }
                let frames = Self.drain(accumulator, appending: data)
                for frame in frames {
                    continuation.yield(WitnessAttestation(rawValue: frame))
                }
                if !frames.isEmpty {
                    accumulators[peer] = nil
                    await channel.disconnect(peer)
                }
            case let .peerDisconnected(peer):
                accumulators[peer] = nil
            }
        }
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
