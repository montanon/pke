// In-memory single-sign tracker for the witness flow (HLAM-50 #4 / HLAM-130).
//
// `SessionNonceTracker` records the set of `(SessionNonce, WitnessSigningKey)`
// pairs this device has already signed in the current app session. The set
// lives entirely in memory and is cleared on app restart — cross-restart
// persistence (Keychain or SwiftData) is a deferred follow-up; the
// 30-second witness window mitigates the force-quit-then-rejoin attack in
// the meantime (see `context/08_security_assumptions.md`).
//
// The actor exposes three operations:
//
//   * `hasSigned(nonce:witnessKey:)` — read-only check
//   * `recordSigned(nonce:witnessKey:)` — idempotent insert (set semantics)
//   * `claim(nonce:witnessKey:)` — atomic check-and-record; returns `true`
//     when the pair was newly recorded and `false` when this device had
//     already signed for it. This is what the listener (HLAM-129) should
//     call from its sign closure to avoid the TOCTOU window between a
//     separate `hasSigned` / `recordSigned` pair.

import Foundation

public actor SessionNonceTracker {
    private struct Pair: Hashable {
        let nonce: SessionNonce
        let witnessKey: WitnessSigningKey
    }

    private var signed: Set<Pair> = []

    public init() {}

    /// Returns `true` if this device has already signed an attestation for
    /// `(nonce, witnessKey)` during the current app session.
    public func hasSigned(nonce: SessionNonce, witnessKey: WitnessSigningKey) -> Bool {
        signed.contains(Pair(nonce: nonce, witnessKey: witnessKey))
    }

    /// Mark `(nonce, witnessKey)` as signed. Idempotent — a second call
    /// with the same pair is a no-op.
    public func recordSigned(nonce: SessionNonce, witnessKey: WitnessSigningKey) {
        signed.insert(Pair(nonce: nonce, witnessKey: witnessKey))
    }

    /// Atomic check-and-record. Returns `true` if `(nonce, witnessKey)`
    /// was newly recorded, `false` if this device had already signed for
    /// the pair. Use this from a witness sign closure to enforce the
    /// single-sign rule without the TOCTOU window of a separate
    /// `hasSigned` / `recordSigned` call.
    public func claim(nonce: SessionNonce, witnessKey: WitnessSigningKey) -> Bool {
        signed.insert(Pair(nonce: nonce, witnessKey: witnessKey)).inserted
    }
}
