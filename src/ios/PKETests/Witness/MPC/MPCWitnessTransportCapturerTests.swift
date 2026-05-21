// HLAM-158 — acceptance-criteria coverage for
// `MPCWitnessTransport.runCapturer`.
//
// Every test drives a `FakeMPCCapturerChannel` injected through
// `MPCWitnessTransport(channelFactory:)`. The fake is a no-op MPC
// stand-in: tests script its `events` stream and inspect the
// `startAdvertising` / `send` / `disconnect` calls the transport made.
// No MultipeerConnectivity — runs on every CI platform.

import Foundation
import XCTest
@testable import PKEWitness

final class MPCWitnessTransportCapturerTests: XCTestCase {

    // AC #1 — advertises with a random "pke-" + 8 hex display name.
    func test_runCapturer_advertisesWithRandomPKEPrefixedName() async throws {
        let fake = FakeMPCCapturerChannel()
        let transport = MPCWitnessTransport { fake }

        let stream = transport.runCapturer(session: mpcSession())
        fake.finishEvents()
        _ = await collect(stream)

        let names = fake.advertised
        XCTAssertEqual(names.count, 1)
        let name = try XCTUnwrap(names.first)
        XCTAssertTrue(name.hasPrefix("pke-"))
        XCTAssertEqual(name.count, 12)
        XCTAssertTrue(name.dropFirst(4).allSatisfy(\.isHexDigit))
    }

    // AC #1 — distinct random name per session.
    func test_runCapturer_twoSessions_useDistinctNames() async {
        let vendor = FakeChannelVendor()
        let transport = MPCWitnessTransport { vendor.make() }

        let first = transport.runCapturer(session: mpcSession())
        let second = transport.runCapturer(session: mpcSession())
        for channel in vendor.channels {
            channel.finishEvents()
        }
        _ = await collect(first)
        _ = await collect(second)

        let names = vendor.channels.flatMap(\.advertised)
        XCTAssertEqual(names.count, 2)
        XCTAssertNotEqual(names[0], names[1])
    }

    // AC #2 — framed commitment sent on peer connect.
    func test_onPeerConnected_sendsFramedCommitment() async throws {
        let commitment = SnapshotCommitment(rawValue: Data([0xAA, 0xBB, 0xCC]))
        let fake = FakeMPCCapturerChannel()
        let transport = MPCWitnessTransport { fake }

        let stream = transport.runCapturer(session: mpcSession(commitment: commitment))
        fake.emit(.peerConnected(peerA))
        fake.finishEvents()
        _ = await collect(stream)

        let sent = fake.sent
        XCTAssertEqual(sent.count, 1)
        let entry = try XCTUnwrap(sent.first)
        XCTAssertEqual(entry.peer, peerA)
        XCTAssertEqual(try MPCMessageFraming.decode(entry.data), commitment.rawValue)
    }

    // AC #3 — a framed attestation byte is parsed and emitted.
    func test_onAttestationFrame_parsesAndEmitsToStream() async throws {
        let fake = FakeMPCCapturerChannel()
        let transport = MPCWitnessTransport { fake }

        let stream = transport.runCapturer(session: mpcSession())
        fake.emit(.peerConnected(peerA))
        fake.emit(.dataReceived(peer: peerA, data: try frame([0x10, 0x20])))
        fake.finishEvents()

        let received = await collect(stream)
        XCTAssertEqual(received, [WitnessAttestation(rawValue: Data([0x10, 0x20]))])
    }

    // AC #4 — peer disconnected after its attestation is collected.
    func test_peerDisconnectedAfterAttestationReceipt() async throws {
        let fake = FakeMPCCapturerChannel()
        let transport = MPCWitnessTransport { fake }

        let stream = transport.runCapturer(session: mpcSession())
        fake.emit(.peerConnected(peerA))
        fake.emit(.dataReceived(peer: peerA, data: try frame([0x01])))
        fake.finishEvents()
        _ = await collect(stream)

        XCTAssertEqual(fake.disconnected, [peerA])
    }

    // AC #5 — stream finishes cleanly on stop() with zero values.
    func test_streamFinishesOnStop() async {
        let fake = FakeMPCCapturerChannel()
        let transport = MPCWitnessTransport { fake }

        let stream = transport.runCapturer(session: mpcSession())
        await transport.stop()

        let received = await collect(stream)
        XCTAssertTrue(received.isEmpty)
    }

    // AC #5 — stream finishes when the channel's event stream ends.
    func test_streamFinishesWhenChannelEventsEnd() async {
        let fake = FakeMPCCapturerChannel()
        let transport = MPCWitnessTransport { fake }

        let stream = transport.runCapturer(session: mpcSession())
        fake.finishEvents()

        let received = await collect(stream)
        XCTAssertTrue(received.isEmpty)
    }

    // AC #6 — N attestations emitted in submission order.
    func test_N_attestations_emittedInOrder() async throws {
        let fake = FakeMPCCapturerChannel()
        let transport = MPCWitnessTransport { fake }

        let stream = transport.runCapturer(session: mpcSession())
        let peers = (0..<4).map { MPCPeerHandle(id: "pke-peer\($0)") }
        for (index, peer) in peers.enumerated() {
            fake.emit(.peerConnected(peer))
            fake.emit(.dataReceived(peer: peer, data: try frame([UInt8(index)])))
        }
        fake.finishEvents()

        let received = await collect(stream)
        XCTAssertEqual(
            received,
            (0..<4).map { WitnessAttestation(rawValue: Data([UInt8($0)])) }
        )
    }

    // AC #5 edge — runCapturer after stop() yields an empty finished stream.
    func test_stopBeforeRunCapturer_finishesImmediately() async {
        let fake = FakeMPCCapturerChannel()
        let transport = MPCWitnessTransport { fake }

        await transport.stop()
        let stream = transport.runCapturer(session: mpcSession())

        let received = await collect(stream)
        XCTAssertTrue(received.isEmpty)
    }

    // runWitness on a capturer-only transport — see HLAM-159 witness
    // tests for the full witness-flow coverage.
    func test_runWitness_throwsWhenWitnessChannelUnavailable() async {
        let transport = MPCWitnessTransport { FakeMPCCapturerChannel() }
        do {
            try await transport.runWitness { _ in WitnessAttestation(rawValue: Data()) }
            XCTFail("runWitness should throw witnessChannelUnavailable")
        } catch {
            XCTAssertEqual(error as? MPCWitnessTransportError, .witnessChannelUnavailable)
        }
    }

    func test_transportID_isMultipeerConnectivity() {
        let transport = MPCWitnessTransport { FakeMPCCapturerChannel() }
        XCTAssertEqual(transport.transportID, "multipeerconnectivity")
    }
}

// MARK: - Fixtures

private let peerA = MPCPeerHandle(id: "pke-aaaa1111")

private func mpcSession(
    commitment: SnapshotCommitment = SnapshotCommitment(rawValue: Data([0xAA]))
) -> WitnessSession {
    WitnessSession(sessionNonce: SessionNonce(rawValue: Data([0x01])), commitment: commitment)
}

private func frame(_ bytes: [UInt8]) throws -> Data {
    try MPCMessageFraming.encode(Data(bytes))
}

private func collect(_ stream: AsyncStream<WitnessAttestation>) async -> [WitnessAttestation] {
    var out: [WitnessAttestation] = []
    for await attestation in stream {
        out.append(attestation)
    }
    return out
}

// MARK: - Fake channel

/// No-op `MPCCapturerChannel`: tests script `events` and inspect the
/// recorded `startAdvertising` / `send` / `disconnect` calls.
final class FakeMPCCapturerChannel: MPCCapturerChannel, @unchecked Sendable {

    let events: AsyncStream<MPCCapturerEvent>

    private let eventContinuation: AsyncStream<MPCCapturerEvent>.Continuation
    private let lock = NSLock()
    private var advertisedNames: [String] = []
    private var sentPayloads: [(peer: MPCPeerHandle, data: Data)] = []
    private var disconnectedPeers: [MPCPeerHandle] = []
    private var stopped = false

    init() {
        (events, eventContinuation) = AsyncStream<MPCCapturerEvent>.makeStream()
    }

    // MARK: MPCCapturerChannel

    func startAdvertising(displayName: String) async {
        lock.lock()
        advertisedNames.append(displayName)
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

    func emit(_ event: MPCCapturerEvent) {
        eventContinuation.yield(event)
    }

    func finishEvents() {
        eventContinuation.finish()
    }

    // MARK: Recorded calls (thread-safe snapshots)

    var advertised: [String] {
        lock.lock()
        defer { lock.unlock() }
        return advertisedNames
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

/// Vends fresh fakes and retains them for post-run inspection.
final class FakeChannelVendor: @unchecked Sendable {
    private let lock = NSLock()
    private var made: [FakeMPCCapturerChannel] = []

    func make() -> FakeMPCCapturerChannel {
        let channel = FakeMPCCapturerChannel()
        lock.lock()
        made.append(channel)
        lock.unlock()
        return channel
    }

    var channels: [FakeMPCCapturerChannel] {
        lock.lock()
        defer { lock.unlock() }
        return made
    }
}
