// HLAM-158 — real `MCSession`-backed `MPCCapturerChannel`.
//
// Gated `#if canImport(MultipeerConnectivity)` so `PKEWitness` compiles
// to an empty translation unit on Linux CI. The capturer-flow logic in
// `MPCWitnessTransport` is transport-agnostic and tested against a fake
// channel; this file is the on-device wiring and is exercised only by
// compilation on macOS CI until the two-device integration test
// (HLAM-52 Story 7) lands.
//
// The local `MCPeerID` is built from the random `"pke-"` display name
// supplied by the transport. `MCSession` uses `encryptionPreference:
// .required` — every byte over the wire is encrypted. Incoming witness
// invitations are auto-accepted: the capturer's role is to collect
// attestations from any nearby witness, and peer identity is
// established by the signed payload, not by the MPC layer.

#if canImport(MultipeerConnectivity)
import Foundation
import MultipeerConnectivity

public final class MPCSessionCapturerChannel: MPCCapturerChannel, @unchecked Sendable {

    public let events: AsyncStream<MPCCapturerEvent>

    private let bridge: MPCCapturerBridge
    private let continuation: AsyncStream<MPCCapturerEvent>.Continuation
    private let lock = NSLock()
    private var session: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var isStopped = false

    public init() {
        let (stream, continuation) = AsyncStream<MPCCapturerEvent>.makeStream()
        self.events = stream
        self.continuation = continuation
        self.bridge = MPCCapturerBridge(continuation: continuation)
    }

    public func startAdvertising(displayName: String) async {
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

        let advertiser = MCNearbyServiceAdvertiser(
            peer: peerID,
            discoveryInfo: nil,
            serviceType: MPCWitnessTransport.serviceType
        )
        advertiser.delegate = bridge

        self.session = session
        self.advertiser = advertiser
        advertiser.startAdvertisingPeer()
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
        // whole-session `disconnect()`, which would drop the other
        // witnesses the dispatcher is rotating through its 30s window.
        // The witness side tears the connection down after sending its
        // attestation (HLAM-159); here the peer mapping is simply
        // forgotten so a late frame from it is ignored.
        bridge.forget(peer.id)
    }

    public func stop() async {
        lock.lock()
        let alreadyStopped = isStopped
        isStopped = true
        let advertiser = self.advertiser
        let session = self.session
        self.advertiser = nil
        self.session = nil
        lock.unlock()

        guard !alreadyStopped else { return }
        advertiser?.stopAdvertisingPeer()
        session?.disconnect()
        continuation.finish()
    }
}

// MARK: - Delegate bridge

/// Routes `MCSessionDelegate` + `MCNearbyServiceAdvertiserDelegate`
/// callbacks (which fire on arbitrary framework threads) onto the
/// channel's `AsyncStream` continuation, which is the single
/// synchronization point.
final class MPCCapturerBridge: NSObject, @unchecked Sendable {

    private let continuation: AsyncStream<MPCCapturerEvent>.Continuation
    private let lock = NSLock()
    private weak var session: MCSession?
    private var peerIDs: [String: MCPeerID] = [:]

    init(continuation: AsyncStream<MPCCapturerEvent>.Continuation) {
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

extension MPCCapturerBridge: MCSessionDelegate {

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

extension MPCCapturerBridge: MCNearbyServiceAdvertiserDelegate {

    func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didReceiveInvitationFromPeer peerID: MCPeerID,
        withContext context: Data?,
        invitationHandler: @escaping (Bool, MCSession?) -> Void
    ) {
        lock.lock()
        let session = self.session
        lock.unlock()
        // Auto-accept: any nearby witness may attest. Identity is
        // verified by the signed payload, not the MPC layer.
        invitationHandler(session != nil, session)
    }

    func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didNotStartAdvertisingPeer error: any Error
    ) {}
}
#endif
