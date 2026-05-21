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
// HLAM-159 adds the witness role (`runWitness`). It mirrors the capturer
// design: the flow is decoupled from MultipeerConnectivity behind the
// `MPCWitnessChannel` seam (browser side) — discovery / data events,
// framed sends, and a single `stop()`. The real `MCNearbyServiceBrowser`-
// backed conformer (`MPCSessionWitnessChannel`) is
// `#if canImport(MultipeerConnectivity)`-gated; unit tests inject a fake.

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

/// Events surfaced by an `MPCWitnessChannel` while browsing.
public enum MPCWitnessEvent: Sendable {
    case peerConnected(MPCPeerHandle)
    case dataReceived(peer: MPCPeerHandle, data: Data)
    case peerDisconnected(MPCPeerHandle)
}

/// Witness-side seam over an MPC session: browse for capturers, observe
/// peer events, send framed payloads, disconnect peers, and tear down.
/// Conformers are reference types so the transport can track active
/// channels by identity.
public protocol MPCWitnessChannel: AnyObject, Sendable {
    /// Connection / data / disconnection events for discovered peers.
    /// Finishes when `stop()` is called.
    var events: AsyncStream<MPCWitnessEvent> { get }

    /// Begin browsing for advertised capturers under `displayName`.
    func startBrowsing(displayName: String) async

    /// Send an already-framed payload to a single connected peer.
    func send(_ data: Data, toPeer peer: MPCPeerHandle) async

    /// Drop a single peer once its attestation has been delivered.
    func disconnect(_ peer: MPCPeerHandle) async

    /// Stop browsing, disconnect everyone, and finish `events`.
    func stop() async
}

public enum MPCWitnessTransportError: Error, Equatable, Sendable {
    /// `runWitness` was called on a transport constructed without a
    /// witness channel factory (capturer-only construction).
    case witnessChannelUnavailable
}

/// `MultipeerConnectivity` witness transport — foreground-primary
/// witness path. Implements both roles: `runCapturer` (advertise) and
/// `runWitness` (browse). A capturer-only transport may omit the
/// witness channel factory; `runWitness` then throws
/// `MPCWitnessTransportError.witnessChannelUnavailable`.
public actor MPCWitnessTransport: WitnessTransport {

    /// MPC service type — ≤15 chars, lowercase + hyphens per MPC rules.
    public static let serviceType = "pke-witness"

    /// `NSBonjourServices` Info.plist entries for `serviceType`.
    public static let bonjourServices = ["_pke-witness._tcp", "_pke-witness._udp"]

    /// Per-connection idle timeout (HLAM-52 Story 6 — not enforced here).
    public static let perConnectionIdleTimeout: TimeInterval = 5

    nonisolated public var transportID: String { "multipeerconnectivity" }

    private let channelFactory: @Sendable () -> any MPCCapturerChannel
    private let witnessChannelFactory: (@Sendable () -> any MPCWitnessChannel)?
    private var activeChannels: [any MPCCapturerChannel] = []
    private var activeWitnessChannels: [any MPCWitnessChannel] = []
    private var isStopped = false

    /// Designated initializer. `channelFactory` vends one channel per
    /// `runCapturer` call; `witnessChannelFactory` vends one per
    /// `runWitness` call. Tests inject fakes here; a capturer-only
    /// transport may omit `witnessChannelFactory`.
    public init(
        channelFactory: @escaping @Sendable () -> any MPCCapturerChannel,
        witnessChannelFactory: (@Sendable () -> any MPCWitnessChannel)? = nil
    ) {
        self.channelFactory = channelFactory
        self.witnessChannelFactory = witnessChannelFactory
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
        guard let witnessChannelFactory else {
            throw MPCWitnessTransportError.witnessChannelUnavailable
        }
        guard !isStopped else { return }
        let channel = witnessChannelFactory()
        activeWitnessChannels.append(channel)
        await channel.startBrowsing(displayName: Self.makeDisplayName())
        do {
            try await driveWitness(channel: channel, sign: sign)
        } catch {
            await teardownWitness(channel: channel)
            throw error
        }
        await teardownWitness(channel: channel)
    }

    public func stop() async {
        isStopped = true
        let channels = activeChannels
        let witnessChannels = activeWitnessChannels
        activeChannels.removeAll()
        activeWitnessChannels.removeAll()
        for channel in channels {
            await channel.stop()
        }
        for channel in witnessChannels {
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

    // MARK: - Witness flow

    private func driveWitness(
        channel: any MPCWitnessChannel,
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {
        var accumulators: [MPCPeerHandle: MPCFrameAccumulator] = [:]
        var servedPeers: Set<MPCPeerHandle> = []
        for await event in channel.events {
            switch event {
            case let .peerConnected(peer):
                accumulators[peer] = MPCFrameAccumulator()
            case let .dataReceived(peer, data):
                guard !servedPeers.contains(peer),
                      let accumulator = accumulators[peer] else { continue }
                let frames: [Data]
                do {
                    frames = try accumulator.append(data)
                } catch {
                    // Poisoned accumulator (oversize declared length) —
                    // drop the peer rather than buffer unbounded bytes.
                    accumulators[peer] = nil
                    await channel.disconnect(peer)
                    continue
                }
                guard let commitmentFrame = frames.first else { continue }
                accumulators[peer] = nil
                servedPeers.insert(peer)
                try await respond(
                    channel: channel,
                    peer: peer,
                    commitment: commitmentFrame,
                    sign: sign
                )
            case let .peerDisconnected(peer):
                accumulators[peer] = nil
            }
        }
    }

    /// Builds the `WitnessSession`, invokes `sign`, frames the returned
    /// attestation, sends it back over the same session, and drops the
    /// peer (AC #3–#5). The capturer wire format carries only the
    /// commitment, so the session nonce is empty here.
    private func respond(
        channel: any MPCWitnessChannel,
        peer: MPCPeerHandle,
        commitment: Data,
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws {
        let session = WitnessSession(
            sessionNonce: SessionNonce(rawValue: Data()),
            commitment: SnapshotCommitment(rawValue: commitment)
        )
        let attestation = try await sign(session)
        let frame: Data
        do {
            frame = try MPCMessageFraming.encode(attestation.rawValue)
        } catch {
            await channel.disconnect(peer)
            return
        }
        await channel.send(frame, toPeer: peer)
        await channel.disconnect(peer)
    }

    private func teardownWitness(channel: any MPCWitnessChannel) async {
        await channel.stop()
        activeWitnessChannels.removeAll { $0 === channel }
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
    /// channels for both roles. Available only where
    /// MultipeerConnectivity exists.
    public init() {
        self.init(
            channelFactory: { MPCSessionCapturerChannel() },
            witnessChannelFactory: { MPCSessionWitnessChannel() }
        )
    }
}
#endif
