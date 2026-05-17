// Capturer-supplied / witness-received envelope binding a session nonce
// to the snapshot commitment being attested over. Carried opaquely by any
// `WitnessTransport`.
//
// Placeholder payload types (`SessionNonce`, `SnapshotCommitment`,
// `WitnessAttestation`) live in `WitnessTypes.swift` until HLAM-36 lands the
// canonical `PKEProtocol` Codable types. At that point this target should
// take a dependency on `PKEProtocol` and `WitnessTypes.swift` should be
// withdrawn.

import Foundation

public struct WitnessSession: Sendable {
    public let sessionNonce: SessionNonce
    public let commitment: SnapshotCommitment

    public init(sessionNonce: SessionNonce, commitment: SnapshotCommitment) {
        self.sessionNonce = sessionNonce
        self.commitment = commitment
    }
}
