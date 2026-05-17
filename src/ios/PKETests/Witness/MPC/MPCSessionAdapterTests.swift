// HLAM-156 — `MPCSessionAdapter` tests.
//
// The four ACs are exercised at three layers:
//
//   * AC #1 / #2 — Configuration: construct the adapter and assert on the
//     `MCSession`'s `encryptionPreference` and both nearby-service types'
//     `serviceType`. Real MCSession / MCNearbyService objects are
//     instantiated; no peer-to-peer traffic is required.
//
//   * AC #3 / #4 — Delegate routing + actor isolation: build a
//     standalone `MPCSessionBridge` paired with an `AsyncStream` that
//     the test owns directly, then call the three delegate protocol
//     methods. Each callback must yield exactly one corresponding
//     `MPCSessionAdapter.Event` on the stream — no race, no drop, no
//     out-of-order routing. The adapter-managed bridge is exercised via
//     the public `events` stream in the configuration tests so the
//     end-to-end routing is also covered.
//
// The suite is gated on `canImport(MultipeerConnectivity)` so the file
// compiles to an empty translation unit on Linux.

#if canImport(MultipeerConnectivity)
import Foundation
import MultipeerConnectivity
import XCTest
@testable import PKEWitness

final class MPCSessionAdapterTests: XCTestCase {

    // MARK: - Test fixtures

    private func makePeer(name: String = "pke-test-peer") -> MCPeerID {
        MCPeerID(displayName: name)
    }

    private func makeAdapter(name: String = "pke-test-peer") -> MPCSessionAdapter {
        MPCSessionAdapter(localPeer: makePeer(name: name))
    }

    // MARK: AC #1 — MCSession encryption preference is .required

    func test_session_isConfiguredWithEncryptionRequired() async {
        let adapter = makeAdapter()
        let pref = await adapter.encryptionPreference
        XCTAssertEqual(pref, .required)
        await adapter.stop()
    }

    // MARK: AC #2 — advertiser + browser use serviceType "pke-witness"

    func test_advertiser_usesPKEWitnessServiceType() async {
        let adapter = makeAdapter()
        let serviceType = await adapter.advertiserServiceType
        XCTAssertEqual(serviceType, "pke-witness")
        XCTAssertEqual(MPCSessionAdapter.serviceType, "pke-witness")
        await adapter.stop()
    }

    func test_browser_usesPKEWitnessServiceType() async {
        let adapter = makeAdapter()
        let serviceType = await adapter.browserServiceType
        XCTAssertEqual(serviceType, "pke-witness")
        await adapter.stop()
    }

    // MARK: AC #3 — MCSessionDelegate callbacks route into the event stream

    func test_sessionDelegate_peerStateChanged_yieldsRoutedEvent() async throws {
        let (bridge, _, events) = makeBridgeFixture()
        let peer = makePeer(name: "remote-1")

        bridge.session(makeStandaloneSession(), peer: peer, didChange: .connected)

        let event = try await firstEvent(from: events)
        guard case let .peerStateChanged(observedPeer, observedState) = event else {
            XCTFail("expected .peerStateChanged; got \(event)")
            return
        }
        XCTAssertEqual(observedPeer, peer)
        XCTAssertEqual(observedState, .connected)
    }

    func test_sessionDelegate_didReceiveData_yieldsRoutedEvent() async throws {
        let (bridge, _, events) = makeBridgeFixture()
        let peer = makePeer(name: "remote-data")
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])

        bridge.session(makeStandaloneSession(), didReceive: payload, fromPeer: peer)

        let event = try await firstEvent(from: events)
        guard case let .dataReceived(observedPeer, observedData) = event else {
            XCTFail("expected .dataReceived; got \(event)")
            return
        }
        XCTAssertEqual(observedPeer, peer)
        XCTAssertEqual(observedData, payload)
    }

    // MARK: AC #3 — MCNearbyServiceBrowserDelegate callbacks route

    func test_browserDelegate_foundPeer_yieldsRoutedEvent() async throws {
        let (bridge, session, events) = makeBridgeFixture()
        let peer = makePeer(name: "remote-found")
        let info = ["role": "witness"]
        let browser = MCNearbyServiceBrowser(peer: session.myPeerID, serviceType: MPCSessionAdapter.serviceType)

        bridge.browser(browser, foundPeer: peer, withDiscoveryInfo: info)

        let event = try await firstEvent(from: events)
        guard case let .foundPeer(observedPeer, observedInfo) = event else {
            XCTFail("expected .foundPeer; got \(event)")
            return
        }
        XCTAssertEqual(observedPeer, peer)
        XCTAssertEqual(observedInfo, info)
    }

    func test_browserDelegate_lostPeer_yieldsRoutedEvent() async throws {
        let (bridge, session, events) = makeBridgeFixture()
        let peer = makePeer(name: "remote-lost")
        let browser = MCNearbyServiceBrowser(peer: session.myPeerID, serviceType: MPCSessionAdapter.serviceType)

        bridge.browser(browser, lostPeer: peer)

        let event = try await firstEvent(from: events)
        guard case let .lostPeer(observedPeer) = event else {
            XCTFail("expected .lostPeer; got \(event)")
            return
        }
        XCTAssertEqual(observedPeer, peer)
    }

    // MARK: AC #3 — MCNearbyServiceAdvertiserDelegate callback routes with token

    func test_advertiserDelegate_didReceiveInvitation_yieldsInvitationToken() async throws {
        let (bridge, session, events) = makeBridgeFixture()
        let peer = makePeer(name: "remote-inviter")
        let context = Data([0xAB, 0xCD])
        let advertiser = MCNearbyServiceAdvertiser(
            peer: session.myPeerID,
            discoveryInfo: nil,
            serviceType: MPCSessionAdapter.serviceType
        )

        let handlerCalled = HandlerProbe()
        let handler: (Bool, MCSession?) -> Void = { accept, _ in
            handlerCalled.record(accept: accept)
        }

        bridge.advertiser(
            advertiser,
            didReceiveInvitationFromPeer: peer,
            withContext: context,
            invitationHandler: handler
        )

        let event = try await firstEvent(from: events)
        guard case let .invitationReceived(observedPeer, observedContext, token) = event else {
            XCTFail("expected .invitationReceived; got \(event)")
            return
        }
        XCTAssertEqual(observedPeer, peer)
        XCTAssertEqual(observedContext, context)

        token.settle(accept: true)
        XCTAssertEqual(handlerCalled.calls, [true])

        // A second settle is a no-op — MPC requires exactly one call.
        token.settle(accept: false)
        XCTAssertEqual(handlerCalled.calls, [true])
    }

    // MARK: AC #4 — routed events flow through the adapter's own stream

    func test_adapterEventsStream_receivesRoutedEvents() async throws {
        let adapter = makeAdapter(name: "stream-host")
        let events = adapter.events
        let bridge = adapter.bridge
        let peer = makePeer(name: "remote-via-adapter")

        bridge.session(makeStandaloneSession(), peer: peer, didChange: .notConnected)

        let event = try await firstEvent(from: events)
        guard case let .peerStateChanged(observedPeer, observedState) = event else {
            XCTFail("expected .peerStateChanged via adapter stream; got \(event)")
            return
        }
        XCTAssertEqual(observedPeer, peer)
        XCTAssertEqual(observedState, .notConnected)

        await adapter.stop()
    }

    // MARK: AC #4 — concurrent delegate yields land serially on the stream

    func test_concurrentDelegateCallbacks_landSeriallyOnStream() async throws {
        let (bridge, _, events) = makeBridgeFixture()
        let session = makeStandaloneSession()
        let payloads = (0..<32).map { Data([UInt8($0)]) }
        let peer = makePeer(name: "remote-concurrent")

        await withTaskGroup(of: Void.self) { group in
            for payload in payloads {
                group.addTask {
                    bridge.session(session, didReceive: payload, fromPeer: peer)
                }
            }
        }

        var observed: [Data] = []
        var iterator = events.makeAsyncIterator()
        for _ in 0..<payloads.count {
            guard let next = await iterator.next() else {
                XCTFail("stream finished early; expected \(payloads.count) events")
                return
            }
            guard case let .dataReceived(_, data) = next else {
                XCTFail("expected .dataReceived; got \(next)")
                return
            }
            observed.append(data)
        }
        XCTAssertEqual(Set(observed), Set(payloads))
    }
}

// MARK: - Helpers

#if canImport(MultipeerConnectivity)

private extension MPCSessionAdapterTests {

    /// Standalone bridge + matching session + event stream — used for
    /// direct routing tests that do not need the actor.
    func makeBridgeFixture() -> (MPCSessionBridge, MCSession, AsyncStream<MPCSessionAdapter.Event>) {
        let session = makeStandaloneSession()
        let (stream, continuation) = AsyncStream<MPCSessionAdapter.Event>.makeStream()
        let bridge = MPCSessionBridge(continuation: continuation, session: session)
        return (bridge, session, stream)
    }

    func makeStandaloneSession() -> MCSession {
        MCSession(
            peer: makePeer(name: "fixture-peer"),
            securityIdentity: nil,
            encryptionPreference: .required
        )
    }

    /// Drains the first event from `events`. The bridge yields
    /// synchronously inside its delegate callbacks, so by the time the
    /// caller awaits `iterator.next()` the event is already in the
    /// stream's buffer — no explicit timeout is needed. Returning `nil`
    /// here only happens if the stream itself finished, which the
    /// caller treats as a test failure.
    func firstEvent(
        from events: AsyncStream<MPCSessionAdapter.Event>
    ) async throws -> MPCSessionAdapter.Event {
        var iterator = events.makeAsyncIterator()
        guard let event = await iterator.next() else {
            throw StreamFinishedBeforeYield()
        }
        return event
    }
}

private struct StreamFinishedBeforeYield: Error {}

/// Locked counter so the invitation-handler probe is observable from
/// the test thread without a race.
private final class HandlerProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var observedCalls: [Bool] = []

    func record(accept: Bool) {
        lock.lock()
        observedCalls.append(accept)
        lock.unlock()
    }

    var calls: [Bool] {
        lock.lock()
        defer { lock.unlock() }
        return observedCalls
    }
}
#endif
#endif
