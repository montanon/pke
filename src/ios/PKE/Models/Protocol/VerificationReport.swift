// Swift mirror of `pke_backend.protocol.VerificationReport`. The verifier
// summarises which integrity checks passed and aggregates witness signals.
// All result booleans are required; `attestation_summary` is optional and
// its nested fields may be absent on partial verifications.

import Foundation
import PKECrypto

public struct VerificationReport: Codable, Equatable, Sendable {

    public static let typeName = "verification_report"

    public let type: String
    public let version: String
    public let snapshotId: String
    public let results: Results
    public let attestationSummary: AttestationSummary?
    public let limitations: [String]

    public init(
        version: String,
        snapshotId: String,
        results: Results,
        attestationSummary: AttestationSummary?,
        limitations: [String]
    ) {
        self.type = Self.typeName
        self.version = version
        self.snapshotId = snapshotId
        self.results = results
        self.attestationSummary = attestationSummary
        self.limitations = limitations
    }

    public struct Results: Codable, Equatable, Sendable {

        public let ciphertextHashVerified: Bool
        public let ownerSignatureVerified: Bool
        public let witnessSignaturesVerified: Bool
        public let ledgerHashChainVerified: Bool
        public let recipientKeyGrantVerified: Bool

        public init(
            ciphertextHashVerified: Bool,
            ownerSignatureVerified: Bool,
            witnessSignaturesVerified: Bool,
            ledgerHashChainVerified: Bool,
            recipientKeyGrantVerified: Bool
        ) {
            self.ciphertextHashVerified = ciphertextHashVerified
            self.ownerSignatureVerified = ownerSignatureVerified
            self.witnessSignaturesVerified = witnessSignaturesVerified
            self.ledgerHashChainVerified = ledgerHashChainVerified
            self.recipientKeyGrantVerified = recipientKeyGrantVerified
        }

        enum CodingKeys: String, CodingKey, CaseIterable {
            case ciphertextHashVerified = "ciphertext_hash_verified"
            case ownerSignatureVerified = "owner_signature_verified"
            case witnessSignaturesVerified = "witness_signatures_verified"
            case ledgerHashChainVerified = "ledger_hash_chain_verified"
            case recipientKeyGrantVerified = "recipient_key_grant_verified"
        }

        public init(from decoder: Decoder) throws {
            try requireNoUnknownKeys(in: decoder, against: CodingKeys.self)
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.ciphertextHashVerified = try container.decode(
                Bool.self,
                forKey: .ciphertextHashVerified
            )
            self.ownerSignatureVerified = try container.decode(
                Bool.self,
                forKey: .ownerSignatureVerified
            )
            self.witnessSignaturesVerified = try container.decode(
                Bool.self,
                forKey: .witnessSignaturesVerified
            )
            self.ledgerHashChainVerified = try container.decode(
                Bool.self,
                forKey: .ledgerHashChainVerified
            )
            self.recipientKeyGrantVerified = try container.decode(
                Bool.self,
                forKey: .recipientKeyGrantVerified
            )
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(ciphertextHashVerified, forKey: .ciphertextHashVerified)
            try container.encode(ownerSignatureVerified, forKey: .ownerSignatureVerified)
            try container.encode(witnessSignaturesVerified, forKey: .witnessSignaturesVerified)
            try container.encode(ledgerHashChainVerified, forKey: .ledgerHashChainVerified)
            try container.encode(recipientKeyGrantVerified, forKey: .recipientKeyGrantVerified)
        }
    }

    public struct AttestationSummary: Codable, Equatable, Sendable {

        public let witnessCount: Int?
        public let transport: String?
        public let attestationStrength: AttestationStrength?

        public init(
            witnessCount: Int?,
            transport: String?,
            attestationStrength: AttestationStrength?
        ) {
            self.witnessCount = witnessCount
            self.transport = transport
            self.attestationStrength = attestationStrength
        }

        enum CodingKeys: String, CodingKey, CaseIterable {
            case witnessCount = "witness_count"
            case transport
            case attestationStrength = "attestation_strength"
        }

        public init(from decoder: Decoder) throws {
            try requireNoUnknownKeys(in: decoder, against: CodingKeys.self)
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.witnessCount = try container.decodeIfPresent(Int.self, forKey: .witnessCount)
            self.transport = try container.decodeIfPresent(String.self, forKey: .transport)
            self.attestationStrength = try container.decodeIfPresent(
                AttestationStrength.self,
                forKey: .attestationStrength
            )
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encodeIfPresent(witnessCount, forKey: .witnessCount)
            try container.encodeIfPresent(transport, forKey: .transport)
            try container.encodeIfPresent(attestationStrength, forKey: .attestationStrength)
        }
    }

    public enum AttestationStrength: String, Codable, CaseIterable, Sendable {
        case none
        case low
        case medium
        case high
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case version
        case snapshotId = "snapshot_id"
        case results
        case attestationSummary = "attestation_summary"
        case limitations
    }

    public init(from decoder: Decoder) throws {
        try requireNoUnknownKeys(in: decoder, against: CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawType = try container.decode(String.self, forKey: .type)
        guard rawType == Self.typeName else {
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "expected '\(Self.typeName)', got '\(rawType)'"
            )
        }
        self.type = rawType
        self.version = try container.decode(String.self, forKey: .version)
        self.snapshotId = try container.decode(String.self, forKey: .snapshotId)
        self.results = try container.decode(Results.self, forKey: .results)
        self.attestationSummary = try container.decodeIfPresent(
            AttestationSummary.self,
            forKey: .attestationSummary
        )
        self.limitations = try container.decode([String].self, forKey: .limitations)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(version, forKey: .version)
        try container.encode(snapshotId, forKey: .snapshotId)
        try container.encode(results, forKey: .results)
        try container.encodeIfPresent(attestationSummary, forKey: .attestationSummary)
        try container.encode(limitations, forKey: .limitations)
    }
}
