// HLAM-159 — acceptance-criteria coverage for
// `MPCWitnessTransport.runWitness`.
//
// Every test drives a `FakeMPCWitnessChannel` injected through
// `MPCWitnessTransport(channelFactory:witnessChannelFactory:)`. The fake
// is a no-op MPC stand-in: tests script its `events` stream and inspect
// the `startBrowsing` / `send` / `disconnect` calls the transport made.
// No MultipeerConnectivity — runs on every CI platform.
//
// The capturer-side `FakeMPCCapturerChannel` (from
// `MPCWitnessTransportCapturerTests`) is reused for the round-trip test.

import Foundation
import XCTest
@testable import PKEWitness

final class MPCWitnessTransportWitnessTests: XCTestCase {

    // AC #1 — browses with a random "pke-" + 8 hex display name.
    func test_runWitness_browsesWithRandomPKEPrefixedName() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        fake.finishEvents()
        try await task.value

        let names = fake.browsed
        XCTAssertEqual(names.count, 1)
        let name = try XCTUnwrap(names.first)
        XCTAssertTrue(name.hasPrefix("pke-"))
        XCTAssertEqual(name.count, 12)
        XCTAssertTrue(name.dropFirst(4).allSatisfy(\.isHexDigit))
    }

    // AC #1 — distinct random name per session.
    func test_runWitness_twoSessions_useDistinctNames() async throws {
        let vendor = FakeWitnessChannelVendor()
        let transport = MPCWitnessTransport(
            channelFactory: { FakeMPCCapturerChannel() },
            witnessChannelFactory: { vendor.make() }
        )

        let first = Task { try await transport.runWitness(sign: signing.sign) }
        let second = Task { try await transport.runWitness(sign: signing.sign) }
        // Both runWitness tasks call vendor.make() lazily once they enter
        // the actor — wait until both channels exist before finishing them.
        await poll { vendor.channels.count == 2 }
        for channel in vendor.channels {
            channel.finishEvents()
        }
        try await first.value
        try await second.value

        let names = vendor.channels.flatMap(\.browsed)
        XCTAssertEqual(names.count, 2)
        XCTAssertNotEqual(names[0], names[1])
    }

    // AC #3 — a framed commitment is decoded and handed to `sign`.
    func test_onCommitmentFrame_decodesAndInvokesSign() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        fake.emit(.peerConnected(peerW))
        fake.emit(.dataReceived(peer: peerW, data: try frame([0xAA, 0xBB])))
        fake.finishEvents()
        try await task.value

        XCTAssertEqual(signing.sessions.count, 1)
        XCTAssertEqual(
            signing.sessions.first?.commitment,
            SnapshotCommitment(rawValue: Data([0xAA, 0xBB]))
        )
    }

    // The capturer wire format carries no nonce — the session nonce is empty.
    func test_onCommitmentFrame_buildsSessionWithEmptyNonce() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        fake.emit(.peerConnected(peerW))
        fake.emit(.dataReceived(peer: peerW, data: try frame([0x01])))
        fake.finishEvents()
        try await task.value

        XCTAssertEqual(signing.sessions.first?.sessionNonce, SessionNonce(rawValue: Data()))
    }

    // AC #4 — the returned attestation is framed and sent to the same peer.
    func test_onSign_sendsFramedAttestationToSamePeer() async throws {
        let fake = FakeMPCWitnessChannel()
        let recorder = SignRecorder(attestation: WitnessAttestation(rawValue: Data([0x10, 0x20])))
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: recorder.sign) }
        fake.emit(.peerConnected(peerW))
        fake.emit(.dataReceived(peer: peerW, data: try frame([0x01])))
        fake.finishEvents()
        try await task.value

        XCTAssertEqual(fake.sent.count, 1)
        let entry = try XCTUnwrap(fake.sent.first)
        XCTAssertEqual(entry.peer, peerW)
        XCTAssertEqual(try MPCMessageFraming.decode(entry.data), Data([0x10, 0x20]))
    }

    // AC #5 — the peer is disconnected once its attestation is sent.
    func test_onSign_disconnectsPeerAfterSending() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        fake.emit(.peerConnected(peerW))
        fake.emit(.dataReceived(peer: peerW, data: try frame([0x01])))
        fake.finishEvents()
        try await task.value

        XCTAssertEqual(fake.disconnected, [peerW])
    }

    // AC #6 — runWitness returns when stop() is called.
    func test_runWitness_returnsWhenStopIsCalled() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        // Browsing started ⇒ the channel is registered for stop() to reach.
        await poll { !fake.browsed.isEmpty }
        await transport.stop()
        try await task.value

        XCTAssertTrue(signing.sessions.isEmpty)
    }

    // Edge — stop() before runWitness returns without browsing.
    func test_stopBeforeRunWitness_returnsWithoutBrowsing() async throws {
        let vendor = FakeWitnessChannelVendor()
        let transport = MPCWitnessTransport(
            channelFactory: { FakeMPCCapturerChannel() },
            witnessChannelFactory: { vendor.make() }
        )

        await transport.stop()
        try await transport.runWitness(sign: signing.sign)

        XCTAssertTrue(vendor.channels.isEmpty)
    }

    // Edge — runWitness propagates a sign-closure error; no attestation sent.
    func test_runWitness_propagatesSignClosureError() async throws {
        let fake = FakeMPCWitnessChannel()
        let recorder = SignRecorder(error: StubSignError.boom)
        let transport = makeTransport(witness: fake)

        let task = Task<Void, Error> { try await transport.runWitness(sign: recorder.sign) }
        fake.emit(.peerConnected(peerW))
        fake.emit(.dataReceived(peer: peerW, data: try frame([0x01])))

        do {
            try await task.value
            XCTFail("expected sign-closure error to propagate")
        } catch let error as StubSignError {
            XCTAssertEqual(error, .boom)
        }
        XCTAssertTrue(fake.sent.isEmpty)
    }

    // Edge — a poisoned (oversize-declared) frame drops the peer, no sign call.
    func test_onPoisonedFrame_dropsPeerWithoutSigning() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        fake.emit(.peerConnected(peerW))
        // Length prefix claims 0xFFFFFFFF bytes — far over the 1 MiB cap.
        fake.emit(.dataReceived(peer: peerW, data: Data([0xFF, 0xFF, 0xFF, 0xFF, 0x00])))
        fake.finishEvents()
        try await task.value

        XCTAssertTrue(signing.sessions.isEmpty)
        XCTAssertTrue(fake.sent.isEmpty)
        XCTAssertEqual(fake.disconnected, [peerW])
    }

    // Edge — peer disconnects before any commitment: sign never invoked.
    func test_peerDisconnectedBeforeCommitment_doesNotSign() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        fake.emit(.peerConnected(peerW))
        fake.emit(.peerDisconnected(peerW))
        fake.finishEvents()
        try await task.value

        XCTAssertTrue(signing.sessions.isEmpty)
    }

    // Edge — a second commitment from an already-served peer is ignored.
    func test_secondCommitmentFromServedPeer_isIgnored() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        fake.emit(.peerConnected(peerW))
        fake.emit(.dataReceived(peer: peerW, data: try frame([0x01])))
        fake.emit(.dataReceived(peer: peerW, data: try frame([0x02])))
        fake.finishEvents()
        try await task.value

        XCTAssertEqual(signing.sessions.count, 1)
    }

    // Edge — multiple peers in one session are each signed independently.
    func test_multiplePeers_eachSignedAndAnswered() async throws {
        let fake = FakeMPCWitnessChannel()
        let transport = makeTransport(witness: fake)

        let task = Task { try await transport.runWitness(sign: signing.sign) }
        let peers = (0..<3).map { MPCPeerHandle(id: "pke-peer\($0)") }
        for (index, peer) in peers.enumerated() {
            fake.emit(.peerConnected(peer))
            fake.emit(.dataReceived(peer: peer, data: try frame([UInt8(index)])))
        }
        fake.finishEvents()
        try await task.value

        XCTAssertEqual(signing.sessions.count, 3)
        XCTAssertEqual(Set(fake.sent.map(\.peer)), Set(peers))
        XCTAssertEqual(Set(fake.disconnected), Set(peers))
    }

    // DoD — capturer ↔ witness round-trip: the witness signs the capturer's
    // commitment and the attestation arrives back on the capturer's stream.
    func test_roundTrip_capturerWitnessSignAndReturn() async throws {
        let commitment = SnapshotCommitment(rawValue: Data([0xC0, 0xFF, 0xEE]))
        let attestation = WitnessAttestation(rawValue: Data([0xA7, 0x7E, 0x57]))
        let recorder = SignRecorder(attestation: attestation)
        let capturerChannel = FakeMPCCapturerChannel()
        let witnessChannel = FakeMPCWitnessChannel()
        let capturerTransport = MPCWitnessTransport { capturerChannel }
        let witnessTransport = makeTransport(witness: witnessChannel)

        // Capturer advertises and frames the commitment on peer connect.
        let capturerStream = capturerTransport.runCapturer(session: session(commitment))
        capturerChannel.emit(.peerConnected(capturerPeer))
        await poll { !capturerChannel.sent.isEmpty }
        let commitmentFrame = try XCTUnwrap(capturerChannel.sent.first).data

        // Witness consumes the commitment, signs, frames the attestation.
        let witnessTask = Task { try await witnessTransport.runWitness(sign: recorder.sign) }
        witnessChannel.emit(.peerConnected(peerW))
        witnessChannel.emit(.dataReceived(peer: peerW, data: commitmentFrame))
        await poll { !witnessChannel.sent.isEmpty }
        witnessChannel.finishEvents()
        try await witnessTask.value
        let attestationFrame = try XCTUnwrap(witnessChannel.sent.first).data
        XCTAssertEqual(recorder.sessions.map(\.commitment), [commitment])

        // Capturer consumes the attestation frame off the same session.
        capturerChannel.emit(.dataReceived(peer: capturerPeer, data: attestationFrame))
        capturerChannel.finishEvents()
        let received = await collectAttestations(capturerStream)
        XCTAssertEqual(received, [attestation])
    }

    // MARK: - Per-test signing recorder

    private let signing = SignRecorder()
}

// MARK: - Fixtures

private let peerW = MPCPeerHandle(id: "pke-wwww2222")
private let capturerPeer = MPCPeerHandle(id: "pke-cccc3333")

private func makeTransport(witness: FakeMPCWitnessChannel) -> MPCWitnessTransport {
    MPCWitnessTransport(
        channelFactory: { FakeMPCCapturerChannel() },
        witnessChannelFactory: { witness }
    )
}

private func frame(_ bytes: [UInt8]) throws -> Data {
    try MPCMessageFraming.encode(Data(bytes))
}

private func session(_ commitment: SnapshotCommitment) -> WitnessSession {
    WitnessSession(sessionNonce: SessionNonce(rawValue: Data([0x01])), commitment: commitment)
}

private func collectAttestations(
    _ stream: AsyncStream<WitnessAttestation>
) async -> [WitnessAttestation] {
    var out: [WitnessAttestation] = []
    for await attestation in stream {
        out.append(attestation)
    }
    return out
}

/// Yields the cooperative executor until `condition` holds, so a
/// concurrently running transport task can make progress. Bounded so a
/// genuine hang fails the test instead of spinning forever.
private func poll(until condition: () -> Bool) async {
    var iterations = 0
    while !condition(), iterations < 100_000 {
        await Task.yield()
        iterations += 1
    }
}

private enum StubSignError: Error, Equatable {
    case boom
}

// MARK: - Sign recorder

/// Records every `WitnessSession` handed to `sign` and returns a fixed
/// attestation (or throws a fixed error).
private final class SignRecorder: @unchecked Sendable {

    private let lock = NSLock()
    private var recorded: [WitnessSession] = []
    private let attestation: WitnessAttestation
    private let error: (any Error)?

    init(
        attestation: WitnessAttestation = WitnessAttestation(rawValue: Data()),
        error: (any Error)? = nil
    ) {
        self.attestation = attestation
        self.error = error
    }

    var sessions: [WitnessSession] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    @Sendable
    func sign(_ session: WitnessSession) async throws -> WitnessAttestation {
        lock.lock()
        recorded.append(session)
        lock.unlock()
        if let error {
            throw error
        }
        return attestation
    }
}

// MARK: - Fake witness channel

/// No-op `MPCWitnessChannel`: tests script `events` and inspect the
/// recorded `startBrowsing` / `send` / `disconnect` calls.
final class FakeMPCWitnessChannel: MPCWitnessChannel, @unchecked Sendable {

    let events: AsyncStream<MPCWitnessEvent>

    private let eventContinuation: AsyncStream<MPCWitnessEvent>.Continuation
    private let lock = NSLock()
    private var browsedNames: [String] = []
    private var sentPayloads: [(peer: MPCPeerHandle, data: Data)] = []
    private var disconnectedPeers: [MPCPeerHandle] = []
    private var stopped = false

    init() {
        (events, eventContinuation) = AsyncStream<MPCWitnessEvent>.makeStream()
    }

    // MARK: MPCWitnessChannel

    func startBrowsing(displayName: String) async {
        lock.lock()
        browsedNames.append(displayName)
        lock.unlock()
    }

    func send(_ data: Data, toPeer peer: MPCPeerHandle) async {
        lock.lock()
        sentPayloads.append((peer: peer, data: data))
        lock.unlock()
    }

    func disconnect(_ peer: MPCPeerHandle) async {
        lock.lock()
        disconnectedPeers.append(peer)
        lock.unlock()
    }

    func stop() async {
        lock.lock()
        let alreadyStopped = stopped
        stopped = true
        lock.unlock()
        if !alreadyStopped {
            eventContinuation.finish()
        }
    }

    // MARK: Test driver

    func emit(_ event: MPCWitnessEvent) {
        eventContinuation.yield(event)
    }

    func finishEvents() {
        eventContinuation.finish()
    }

    // MARK: Recorded calls (thread-safe snapshots)

    var browsed: [String] {
        lock.lock()
        defer { lock.unlock() }
        return browsedNames
    }

    var sent: [(peer: MPCPeerHandle, data: Data)] {
        lock.lock()
        defer { lock.unlock() }
        return sentPayloads
    }

    var disconnected: [MPCPeerHandle] {
        lock.lock()
        defer { lock.unlock() }
        return disconnectedPeers
    }
}

/// Vends fresh witness fakes and retains them for post-run inspection.
final class FakeWitnessChannelVendor: @unchecked Sendable {

    private let lock = NSLock()
    private var made: [FakeMPCWitnessChannel] = []

    func make() -> FakeMPCWitnessChannel {
        let channel = FakeMPCWitnessChannel()
        lock.lock()
        made.append(channel)
        lock.unlock()
        return channel
    }

    var channels: [FakeMPCWitnessChannel] {
        lock.lock()
        defer { lock.unlock() }
        return made
    }
}
