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
