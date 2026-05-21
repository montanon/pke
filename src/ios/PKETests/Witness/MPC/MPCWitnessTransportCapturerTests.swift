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

    // runWitness is HLAM-159 — placeholder conformance contract.
    func test_runWitness_throwsNotImplemented() async {
        let transport = MPCWitnessTransport { FakeMPCCapturerChannel() }
        do {
            try await transport.runWitness { _ in WitnessAttestation(rawValue: Data()) }
            XCTFail("runWitness should throw witnessRoleNotImplemented")
        } catch {
            XCTAssertEqual(error as? MPCWitnessTransportError, .witnessRoleNotImplemented)
        }
    }

    func test_transportID_isMultipeerConnectivity() {
        let transport = MPCWitnessTransport { FakeMPCCapturerChannel() }
        XCTAssertEqual(transport.transportID, "multipeerconnectivity")
    }

    // MARK: - HLAM-161 — session rotation + idle timeout

    // AC #3 — the per-connection idle timeout is 5 seconds.
    func test_perConnectionIdleTimeout_defaultsToFiveSeconds() {
        XCTAssertEqual(MPCWitnessTransport.perConnectionIdleTimeout, 5)
    }

    // AC #3 / #5 — a peer that connects but never sends an attestation
    // is disconnected once its idle timeout elapses.
    func test_stalledPeer_droppedAfterIdleTimeout() async {
        let fake = FakeMPCCapturerChannel()
        let sleeper = ControllableSleeper()
        let transport = MPCWitnessTransport(
            channelFactory: { fake },
            sleep: { await sleeper.sleep($0) }
        )

        let stream = transport.runCapturer(session: mpcSession())
        fake.emit(.peerConnected(peerA))
        await sleeper.awaitSleepers(count: 1)
        sleeper.fireAll()                       // 5 seconds "elapse"
        fake.finishEvents()

        let received = await collect(stream)
        XCTAssertTrue(received.isEmpty)
        XCTAssertEqual(fake.disconnected, [peerA])
    }

    // AC #5 — rotation: after a stalled peer is dropped, a new peer can
    // still connect and have its attestation collected.
    func test_rotation_newPeerProceedsAfterStalledPeerDropped() async throws {
        let fake = FakeMPCCapturerChannel()
        let sleeper = ControllableSleeper()
        let transport = MPCWitnessTransport(
            channelFactory: { fake },
            sleep: { await sleeper.sleep($0) }
        )

        let stream = transport.runCapturer(session: mpcSession())
        var iterator = stream.makeAsyncIterator()

        fake.emit(.peerConnected(peerA))         // stalls — never attests
        await sleeper.awaitSleepers(count: 1)
        sleeper.fireAll()                        // peerA times out, slot freed

        fake.emit(.peerConnected(peerB))         // rotation: freed slot reused
        await sleeper.awaitSleepers(count: 1)
        fake.emit(.dataReceived(peer: peerB, data: try frame([0x42])))

        // Block until peerB's attestation lands — proves the data event was
        // processed before the leftover timer is fired below.
        let attestation = await iterator.next()
        XCTAssertEqual(attestation, WitnessAttestation(rawValue: Data([0x42])))

        sleeper.fireAll()                        // drain peerB's cancelled timer
        fake.finishEvents()
        while await iterator.next() != nil {}

        XCTAssertTrue(fake.disconnected.contains(peerA))
        XCTAssertTrue(fake.disconnected.contains(peerB))
    }

    // AC #1 / #3 — a peer that attests is disconnected exactly once; a
    // stale idle timeout fired afterwards must not disconnect it again.
    func test_peerThatAttests_notDisconnectedAgainByStaleTimeout() async throws {
        let fake = FakeMPCCapturerChannel()
        let sleeper = ControllableSleeper()
        let transport = MPCWitnessTransport(
            channelFactory: { fake },
            sleep: { await sleeper.sleep($0) }
        )

        let stream = transport.runCapturer(session: mpcSession())
        var iterator = stream.makeAsyncIterator()

        fake.emit(.peerConnected(peerA))
        await sleeper.awaitSleepers(count: 1)
        fake.emit(.dataReceived(peer: peerA, data: try frame([0x07])))

        // Block until the attestation lands — the peer has now completed
        // and its idle timer is cancelled before the stale fire below.
        let attestation = await iterator.next()
        XCTAssertEqual(attestation, WitnessAttestation(rawValue: Data([0x07])))

        sleeper.fireAll()                        // stale timer — must be ignored
        fake.finishEvents()
        while await iterator.next() != nil {}

        XCTAssertEqual(fake.disconnected, [peerA])
    }

    // AC #3 — a timeout that fires after the peer already left on its own
    // must not trigger a spurious disconnect.
    func test_idleTimeout_ignoredAfterPeerDisconnected() async {
        let fake = FakeMPCCapturerChannel()
        let sleeper = ControllableSleeper()
        let transport = MPCWitnessTransport(
            channelFactory: { fake },
            sleep: { await sleeper.sleep($0) }
        )

        let stream = transport.runCapturer(session: mpcSession())
        fake.emit(.peerConnected(peerA))
        await sleeper.awaitSleepers(count: 1)
        fake.emit(.peerDisconnected(peerA))
        fake.finishEvents()

        // collect() drains the stream to completion — every event is
        // processed and the loop has ended before the timer is fired.
        let received = await collect(stream)
        sleeper.fireAll()

        XCTAssertTrue(received.isEmpty)
        XCTAssertTrue(fake.disconnected.isEmpty)
    }
}

// MARK: - Fixtures

private let peerA = MPCPeerHandle(id: "pke-aaaa1111")
private let peerB = MPCPeerHandle(id: "pke-bbbb2222")

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

// MARK: - Controllable sleeper

/// Injectable `sleep` for the transport's idle timer. Every sleep call
/// suspends until the test calls `fireAll()`, so the 5-second timeout is
/// driven deterministically with zero wall-clock waits. `awaitSleepers`
/// lets a test wait until the timer task has actually registered before
/// firing, removing scheduling races.
final class ControllableSleeper: @unchecked Sendable {
    private let lock = NSLock()
    private var pending: [CheckedContinuation<Void, Never>] = []
    private var registrationWaiters: [CheckedContinuation<Void, Never>] = []

    func sleep(_ duration: TimeInterval) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            pending.append(continuation)
            let waiters = registrationWaiters
            registrationWaiters.removeAll()
            lock.unlock()
            for waiter in waiters {
                waiter.resume()
            }
        }
    }

    /// Suspends until at least `count` sleep calls are registered.
    func awaitSleepers(count: Int) async {
        while true {
            lock.lock()
            if pending.count >= count {
                lock.unlock()
                return
            }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                registrationWaiters.append(continuation)
                lock.unlock()
            }
        }
    }

    /// Resumes every currently-suspended sleep — the "timeout elapsed".
    func fireAll() {
        lock.lock()
        let resumable = pending
        pending.removeAll()
        lock.unlock()
        for continuation in resumable {
            continuation.resume()
        }
    }
}
