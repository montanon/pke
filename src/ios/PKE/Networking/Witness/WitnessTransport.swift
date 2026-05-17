// Transport-agnostic seam for the witness flow (HLAM-50 #1).
// Concrete conformers (MPC, BLE, future radios) implement role-specific run
// methods; the higher-level dispatcher (HLAM-50 #2) and listener
// (HLAM-50 #3) consume this protocol without any transport-specific imports.

import Foundation

/// `WitnessTransport` is the plug-in point for every radio used in the
/// witness flow. Role is encoded in the method name (`runCapturer` /
/// `runWitness`) so callers cannot mix up the two sides at compile time.
///
/// `transportID` is stable per transport and used by the dispatcher and
/// listener for logging only — disambiguation between concurrent transports
/// is by instance identity, not by ID. Two transports may share the same ID.
public protocol WitnessTransport: Sendable {
    var transportID: String { get }

    /// Capturer role: advertise the commitment and collect signed
    /// attestations from peers.
    ///
    /// The returned `AsyncStream` emits each `WitnessAttestation` as it
    /// arrives. The stream finishes when `stop()` is called or when the
    /// transport's internal window ends. Calling `stop()` before any
    /// attestation arrives finishes the stream cleanly with zero values.
    ///
    /// Per-attestation errors are an internal concern of the transport and
    /// are not surfaced through the stream — the dispatcher (HLAM-50 #2)
    /// merges streams across transports and cannot reason about per-radio
    /// failure semantics.
    ///
    /// The protocol does not pin an `AsyncStream.Continuation.BufferingPolicy`;
    /// each transport may pick its own (default is `.unbounded`).
    func runCapturer(session: WitnessSession) -> AsyncStream<WitnessAttestation>

    /// Witness role: scan / listen for capturers. On each received
    /// commitment, the transport constructs a `WitnessSession`, invokes
    /// `sign`, and dispatches the returned attestation back to the
    /// capturer over the same transport. Returns when `stop()` is called.
    ///
    /// If `sign` throws, the transport surfaces the error per its own
    /// contract; this protocol does not prescribe retry.
    func runWitness(
        sign: @escaping @Sendable (WitnessSession) async throws -> WitnessAttestation
    ) async throws

    /// Single cancellation entry point. Implementers must terminate any
    /// in-flight `runCapturer` stream and unblock any awaiting `runWitness`.
    func stop() async
}
