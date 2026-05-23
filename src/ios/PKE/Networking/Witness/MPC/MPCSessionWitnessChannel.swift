// HLAM-159 — real `MCNearbyServiceBrowser`-backed `MPCWitnessChannel`.
//
// Gated `#if canImport(MultipeerConnectivity)` so `PKEWitness` compiles
// to an empty translation unit on Linux CI. The witness-flow logic in
// `MPCWitnessTransport` is transport-agnostic and tested against a fake
// channel; this file is the on-device wiring and is exercised only by
// compilation on macOS CI until the two-device integration test
// (HLAM-52 Story 7) lands.
//
// The local `MCPeerID` is built from the random `"pke-"` display name
// supplied by the transport. `MCSession` uses `encryptionPreference:
// .required` — every byte over the wire is encrypted. Discovered
// capturers are auto-invited: the witness's role is to attest for any
// nearby capturer, and peer identity is established by the signed
// payload, not by the MPC layer.

#if canImport(MultipeerConnectivity)
import Foundation
import MultipeerConnectivity

public final class MPCSessionWitnessChannel: MPCWitnessChannel, @unchecked Sendable {

    /// Invitation timeout passed to `MCNearbyServiceBrowser.invitePeer`.
    static let invitationTimeout: TimeInterval = 30

    public let events: AsyncStream<MPCWitnessEvent>

    private let bridge: MPCWitnessBridge
    private let continuation: AsyncStream<MPCWitnessEvent>.Continuation
    private let lock = NSLock()
    private var session: MCSession?
    private var browser: MCNearbyServiceBrowser?
    private var isStopped = false

    public init() {
        let (stream, continuation) = AsyncStream<MPCWitnessEvent>.makeStream()
        self.events = stream
        self.continuation = continuation
        self.bridge = MPCWitnessBridge(continuation: continuation)
    }

    public func startBrowsing(displayName: String) async {
        lock.lock()
        defer { lock.unlock() }
        guard session == nil, !isStopped else { return }

        let peerID = MCPeerID(displayName: displayName)
        let session = MCSession(
            peer: peerID,
            securityIdentity: nil,
            encryptionPreference: .required
        )
        session.delegate = bridge
        bridge.attach(session: session)

        let browser = MCNearbyServiceBrowser(
            peer: peerID,
            serviceType: MPCWitnessTransport.serviceType
        )
        browser.delegate = bridge

        self.session = session
        self.browser = browser
        browser.startBrowsingForPeers()
    }

    public func send(_ data: Data, toPeer peer: MPCPeerHandle) async {
        lock.lock()
        let session = self.session
        lock.unlock()
        guard let session, let peerID = bridge.peerID(for: peer.id) else { return }
        try? session.send(data, toPeers: [peerID], with: .reliable)
    }

    public func disconnect(_ peer: MPCPeerHandle) async {
        // MultipeerConnectivity exposes no per-peer disconnect — only a
        // whole-session `disconnect()`. The witness serves one capturer
        // per session, so forgetting the peer mapping (so a late frame
        // is ignored) is sufficient; full teardown happens in `stop()`.
        bridge.forget(peer.id)
    }

    public func stop() async {
        lock.lock()
        let alreadyStopped = isStopped
        isStopped = true
        let browser = self.browser
        let session = self.session
        self.browser = nil
        self.session = nil
        lock.unlock()

        guard !alreadyStopped else { return }
        browser?.stopBrowsingForPeers()
        session?.disconnect()
        continuation.finish()
    }
}

// MARK: - Delegate bridge

/// Routes `MCSessionDelegate` + `MCNearbyServiceBrowserDelegate`
/// callbacks (which fire on arbitrary framework threads) onto the
/// channel's `AsyncStream` continuation, which is the single
/// synchronization point.
final class MPCWitnessBridge: NSObject, @unchecked Sendable {

    private let continuation: AsyncStream<MPCWitnessEvent>.Continuation
    private let lock = NSLock()
    private weak var session: MCSession?
    private var peerIDs: [String: MCPeerID] = [:]

    init(continuation: AsyncStream<MPCWitnessEvent>.Continuation) {
        self.continuation = continuation
        super.init()
    }

    func attach(session: MCSession) {
        lock.lock()
        self.session = session
        lock.unlock()
    }

    func peerID(for id: String) -> MCPeerID? {
        lock.lock()
        defer { lock.unlock() }
        return peerIDs[id]
    }

    func forget(_ id: String) {
        lock.lock()
        peerIDs[id] = nil
        lock.unlock()
    }

    private func register(_ peerID: MCPeerID) {
        lock.lock()
        peerIDs[peerID.displayName] = peerID
        lock.unlock()
    }
}

extension MPCWitnessBridge: MCSessionDelegate {

    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        let handle = MPCPeerHandle(id: peerID.displayName)
        switch state {
        case .connected:
            register(peerID)
            continuation.yield(.peerConnected(handle))
        case .notConnected:
            forget(peerID.displayName)
            continuation.yield(.peerDisconnected(handle))
        case .connecting:
            break
        @unknown default:
            break
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        continuation.yield(.dataReceived(peer: MPCPeerHandle(id: peerID.displayName), data: data))
    }

    // PKE uses neither streams nor resource transfers — required no-ops.

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

extension MPCWitnessBridge: MCNearbyServiceBrowserDelegate {

    func browser(
        _ browser: MCNearbyServiceBrowser,
        foundPeer peerID: MCPeerID,
        withDiscoveryInfo info: [String: String]?
    ) {
        lock.lock()
        let session = self.session
        lock.unlock()
        // Auto-invite: any nearby capturer may be attested. Identity is
        // verified by the signed payload, not the MPC layer.
        guard let session else { return }
        browser.invitePeer(
            peerID,
            to: session,
            withContext: nil,
            timeout: MPCSessionWitnessChannel.invitationTimeout
        )
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {}

    func browser(
        _ browser: MCNearbyServiceBrowser,
        didNotStartBrowsingForPeers error: any Error
    ) {}
}
#endif
