// HLAM-156 — `MPCSessionAdapter`: actor wrapping `MCSession` + the
// MultipeerConnectivity advertiser / browser bootstrap with all three
// delegate protocols routed onto a single `AsyncStream<Event>` that the
// actor (and downstream MPC transport story HLAM-158 / HLAM-159) can
// consume serially.
//
// Architecture:
//
//   * `MPCSessionAdapter` (actor) — owns the `MCSession`, the
//     `MCNearbyServiceAdvertiser`, the `MCNearbyServiceBrowser`, and an
//     `NSObject` bridge that conforms to the three MPC delegate
//     protocols. Exposes a typed `events` `AsyncStream<Event>` plus
//     explicit `start()` / `stop()` / `send(_:toPeers:)` /
//     `respond(invitationToken:accept:)` operations.
//
//   * `MPCSessionBridge` (final NSObject, internal) — receives the raw
//     callbacks on MPC's internal threads and yields typed `Event`
//     values onto the adapter's shared stream continuation. The bridge
//     captures the continuation by value (Sendable) at init time so it
//     never needs a back-pointer to `self` in the actor.
//
// MPC invitation handlers must be invoked exactly once and synchronously
// from the delegate callback's thread; the adapter cannot funnel the
// decision through actor isolation without dropping the invitation. The
// bridge wraps the invitation handler in a one-shot `InvitationToken`
// keyed by a UUID and yields the token on the stream. Consumers call
// `respond(invitationToken:accept:)` to settle it — that call performs
// the synchronous handler invocation via a sendable closure captured
// inside the token. If no consumer responds before MPC times the
// invitation out, the underlying handler is simply never called and MPC
// drops the request, which matches its documented behavior.
//
// Encryption preference is `.required` per AC #1 — every byte over the
// wire is encrypted by MPC. The `securityIdentity` is `nil` because
// peer identity in PKE is established via the signed payloads carried
// over the channel, not via an X.509 chain on the MPC layer.

#if canImport(MultipeerConnectivity)
import Foundation
import MultipeerConnectivity

public actor MPCSessionAdapter {

    public static let serviceType = "pke-witness"

    /// Typed events emitted by every MPC delegate callback. Consumers
    /// (HLAM-158 / HLAM-159) iterate `events` and pattern-match.
    public enum Event: Sendable {
        case peerStateChanged(peerID: MCPeerID, state: MCSessionState)
        case dataReceived(peerID: MCPeerID, data: Data)
        case foundPeer(peerID: MCPeerID, discoveryInfo: [String: String]?)
        case lostPeer(peerID: MCPeerID)
        case invitationReceived(peerID: MCPeerID, context: Data?, token: InvitationToken)
        case advertiserError(any Error)
        case browserError(any Error)
    }

    /// One-shot wrapper around MPC's invitation handler. The bridge
    /// yields the token; the consumer calls
    /// `MPCSessionAdapter.respond(invitationToken:accept:)` to settle.
    /// Settling twice is a no-op — MPC requires exactly one call to the
    /// handler.
    public final class InvitationToken: @unchecked Sendable {
        public let id: UUID
        private let lock = NSLock()
        private var handler: ((Bool, MCSession?) -> Void)?
        private let session: MCSession

        init(handler: @escaping (Bool, MCSession?) -> Void, session: MCSession) {
            self.id = UUID()
            self.handler = handler
            self.session = session
        }

        /// Invokes the underlying handler exactly once. Subsequent calls
        /// are silently dropped.
        func settle(accept: Bool) {
            lock.lock()
            let captured = handler
            handler = nil
            lock.unlock()
            captured?(accept, accept ? session : nil)
        }
    }

    private let session: MCSession
    private let advertiser: MCNearbyServiceAdvertiser
    private let browser: MCNearbyServiceBrowser
    nonisolated let bridge: MPCSessionBridge
    private nonisolated let continuation: AsyncStream<Event>.Continuation
    private nonisolated let stream: AsyncStream<Event>
    private var isAdvertising = false
    private var isBrowsing = false

    public init(localPeer: MCPeerID) {
        let (stream, continuation) = AsyncStream<Event>.makeStream()
        self.stream = stream
        self.continuation = continuation

        let session = MCSession(
            peer: localPeer,
            securityIdentity: nil,
            encryptionPreference: .required
        )
        self.session = session

        let advertiser = MCNearbyServiceAdvertiser(
            peer: localPeer,
            discoveryInfo: nil,
            serviceType: Self.serviceType
        )
        self.advertiser = advertiser

        let browser = MCNearbyServiceBrowser(
            peer: localPeer,
            serviceType: Self.serviceType
        )
        self.browser = browser

        let bridge = MPCSessionBridge(continuation: continuation, session: session)
        self.bridge = bridge
        session.delegate = bridge
        advertiser.delegate = bridge
        browser.delegate = bridge
    }

    deinit {
        // Only nonisolated state is safe to touch from an actor's deinit;
        // the MCSession / MCNearbyService objects release on their own as
        // their reference counts drop and disconnect on dealloc per the
        // MultipeerConnectivity contract. Finishing the continuation here
        // unblocks any consumer still iterating `events`.
        continuation.finish()
    }

    /// Typed event stream surfacing every routed delegate callback.
    /// Iterating this is the only consumer-side API for receiving MPC
    /// activity — there is no direct delegate seam exposed.
    public nonisolated var events: AsyncStream<Event> { stream }

    /// Read-only configuration accessors. Asynchronous because the
    /// underlying MCSession / MCNearbyService types are not `Sendable`
    /// and the actor-isolated storage cannot be exposed via a
    /// `nonisolated` stored property.
    public var encryptionPreference: MCEncryptionPreference {
        session.encryptionPreference
    }

    public var advertiserServiceType: String { advertiser.serviceType }

    public var browserServiceType: String { browser.serviceType }

    public func startAdvertising() {
        guard !isAdvertising else { return }
        advertiser.startAdvertisingPeer()
        isAdvertising = true
    }

    public func startBrowsing() {
        guard !isBrowsing else { return }
        browser.startBrowsingForPeers()
        isBrowsing = true
    }

    public func stop() {
        if isAdvertising {
            advertiser.stopAdvertisingPeer()
            isAdvertising = false
        }
        if isBrowsing {
            browser.stopBrowsingForPeers()
            isBrowsing = false
        }
        session.disconnect()
        continuation.finish()
    }

    public func send(_ data: Data, toPeers peerIDs: [MCPeerID]) throws {
        try session.send(data, toPeers: peerIDs, with: .reliable)
    }

    public func respond(invitationToken: InvitationToken, accept: Bool) {
        invitationToken.settle(accept: accept)
    }

    public func invite(_ peerID: MCPeerID, withContext context: Data?, timeout: TimeInterval) {
        browser.invitePeer(peerID, to: session, withContext: context, timeout: timeout)
    }
}

// MARK: - Delegate bridge

/// Routes the three MPC delegate protocols into a single typed
/// `AsyncStream` continuation. Lives at module scope so it can be
/// instantiated by `MPCSessionAdapter`'s init without exposing the
/// continuation publicly.
final class MPCSessionBridge: NSObject, @unchecked Sendable {
    private let continuation: AsyncStream<MPCSessionAdapter.Event>.Continuation
    private weak var session: MCSession?

    init(
        continuation: AsyncStream<MPCSessionAdapter.Event>.Continuation,
        session: MCSession
    ) {
        self.continuation = continuation
        self.session = session
    }
}

extension MPCSessionBridge: MCSessionDelegate {

    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        continuation.yield(.peerStateChanged(peerID: peerID, state: state))
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        continuation.yield(.dataReceived(peerID: peerID, data: data))
    }

    // PKE does not use streams or resources — required no-ops for protocol conformance.

    func session(
        _ session: MCSession,
        didReceive stream: InputStream,
        withName streamName: String,
        fromPeer peerID: MCPeerID
    ) {}

    func session(
        _ session: MCSession,
        didStartReceivingResourceWithName resourceName: String,
        fromPeer peerID: MCPeerID,
        with progress: Progress
    ) {}

    func session(
        _ session: MCSession,
        didFinishReceivingResourceWithName resourceName: String,
        fromPeer peerID: MCPeerID,
        at localURL: URL?,
        withError error: (any Error)?
    ) {}
}

extension MPCSessionBridge: MCNearbyServiceAdvertiserDelegate {

    func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didReceiveInvitationFromPeer peerID: MCPeerID,
        withContext context: Data?,
        invitationHandler: @escaping (Bool, MCSession?) -> Void
    ) {
        guard let session else {
            // Adapter was deallocated before the invitation arrived;
            // decline so MPC does not stall the inviter.
            invitationHandler(false, nil)
            return
        }
        let token = MPCSessionAdapter.InvitationToken(
            handler: invitationHandler,
            session: session
        )
        continuation.yield(.invitationReceived(peerID: peerID, context: context, token: token))
    }

    func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didNotStartAdvertisingPeer error: any Error
    ) {
        continuation.yield(.advertiserError(error))
    }
}

extension MPCSessionBridge: MCNearbyServiceBrowserDelegate {

    func browser(
        _ browser: MCNearbyServiceBrowser,
        foundPeer peerID: MCPeerID,
        withDiscoveryInfo info: [String: String]?
    ) {
        continuation.yield(.foundPeer(peerID: peerID, discoveryInfo: info))
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        continuation.yield(.lostPeer(peerID: peerID))
    }

    func browser(_ browser: MCNearbyServiceBrowser, didNotStartBrowsingForPeers error: any Error) {
        continuation.yield(.browserError(error))
    }
}
#endif
