// Placeholder payload types for the witness flow. These exist so HLAM-127
// can ship the `WitnessTransport` seam without blocking on HLAM-36 (the
// Swift `PKEProtocol` Codable types). When HLAM-36 lands, withdraw this
// file and make `PKEWitness` depend on `PKEProtocol`.

import Foundation

public struct SessionNonce: Sendable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }
}

public struct SnapshotCommitment: Sendable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }
}

public struct WitnessAttestation: Sendable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }
}

/// Canonical raw bytes of a witness device's signing public key.
///
/// Carried separately from `PKECrypto.SigningPublicKey` so the
/// `PKEWitness` module does not import `PKECrypto`; the rawValue is the
/// canonical encoded form (P-256 x9.63, 65 bytes) and equality is
/// byte-wise — same rule the wire protocol uses when comparing identities.
public struct WitnessSigningKey: Sendable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }
}
