// Witness-side orchestrator for the witness flow (HLAM-50 #3 / HLAM-129).
//
// `WitnessListener` owns the device-side signing policy. For each registered
// transport it invokes `runWitness(sign:)` with a closure that runs the
// canonical witness pipeline:
//
//   1. Verify the commitment's signature against the inline owner key
//      (delegated to the injected `verifyCommitment` closure).
//   2. Atomically claim `(sessionNonce, witnessKey)` in the
//      `SessionNonceTracker` — if this device has already signed for the
//      pair, throw `WitnessListener.Failure.alreadySigned`. Using the
//      tracker's atomic `claim` avoids the TOCTOU window between a
//      separate `hasSigned` + `recordSigned` pair when the same commitment
//      arrives over MPC and BLE simultaneously.
//   3. Sign the commitment via the injected `sign` closure and return the
//      resulting `WitnessAttestation` for the transport to dispatch back.
//
// Concurrency: declared `actor`; mutable lifecycle state (registered
// transports, in-flight tasks, started/stopped flags) lives behind its
// isolation. The sign closure itself is `@Sendable` and runs in the
// transport's context — that is intentional: parallel transports invoke it
// concurrently and the nonce tracker is what enforces the single-sign rule.
//
// Composition: HLAM-129's Jira description sketches an
// `init(identity: DeviceIdentity, …)` shape. We accept verifier/signer
// closures instead so `PKEWitness` does not have to depend on
// `PKEIdentity` (which is `#if canImport(Security)`-gated and compiles to
// an empty translation unit on Linux). The Apple-only composition root
// wires `DeviceIdentity` and `PKECrypto.Signatures` into the closures
// when constructing the listener.

import Foundation

public actor WitnessListener {
    /// Verifier closure: runs the inline-owner-key signature check on the
    /// commitment carried by `session`. Throwing aborts the witness flow
    /// before any nonce is claimed or attestation produced.
    public typealias VerifyCommitment = @Sendable (WitnessSession) async throws -> Void

    /// Signer closure: produces the signed `WitnessAttestation` for the
    /// already-verified, already-claimed `session`. Throwing surfaces an
    /// error to the transport per its own contract.
    public typealias SignSession = @Sendable (WitnessSession) async throws -> WitnessAttestation

    public enum Failure: Error, Equatable, Sendable {
        /// Raised by the sign closure when this device has already signed an
        /// attestation for the `(sessionNonce, witnessKey)` pair.
        case alreadySigned
    }

    private let nonceTracker: SessionNonceTracker
    private let witnessKey: WitnessSigningKey
    private let verifyCommitment: VerifyCommitment
    private let sign: SignSession
    private var transports: [any WitnessTransport] = []
    private var tasks: [Task<Void, Never>] = []
    private var hasStarted = false
    private var hasStopped = false

    public init(
        nonceTracker: SessionNonceTracker,
        witnessKey: WitnessSigningKey,
        verifyCommitment: @escaping VerifyCommitment,
        sign: @escaping SignSession
    ) {
        self.nonceTracker = nonceTracker
        self.witnessKey = witnessKey
        self.verifyCommitment = verifyCommitment
        self.sign = sign
    }

    /// Add a transport to be used on the next `start()` call. Registrations
    /// after `start()` are ignored — call `stop()` and re-`start()` to pick
    /// up additional transports.
    public func register(_ transport: any WitnessTransport) {
        transports.append(transport)
    }

    /// Run every registered transport in witness role with the canonical
    /// sign closure. Returns once the per-transport tasks are spawned;
    /// each task awaits `transport.runWitness(sign:)` until cancelled or
    /// the transport returns on its own. Idempotent — a second `start()`
    /// is a no-op (documented edge case).
    public func start() {
        guard !hasStarted, !hasStopped else { return }
        hasStarted = true

        let signClosure = makeSignClosure()
        for transport in transports {
            let task = Task {
                do {
                    try await transport.runWitness(sign: signClosure)
                } catch {
                    // A transport-level error must not propagate to peers.
                    // The per-transport contract owns its own retry / log
                    // semantics; the listener absorbs the failure so the
                    // remaining transports keep listening.
                }
            }
            tasks.append(task)
        }
    }

    /// Stop every registered transport and cancel the in-flight listener
    /// tasks. Idempotent.
    public func stop() async {
        guard !hasStopped else { return }
        hasStopped = true
        for task in tasks {
            task.cancel()
        }
        tasks.removeAll()
        for transport in transports {
            await transport.stop()
        }
    }

    private func makeSignClosure() -> SignSession {
        let tracker = nonceTracker
        let key = witnessKey
        let verify = verifyCommitment
        let signer = sign
        return { session in
            try await verify(session)
            let claimed = await tracker.claim(nonce: session.sessionNonce, witnessKey: key)
            guard claimed else {
                throw Failure.alreadySigned
            }
            return try await signer(session)
        }
    }
}
