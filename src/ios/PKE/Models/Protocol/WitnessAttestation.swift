// Swift mirror of `pke_backend.protocol.WitnessAttestation`. A witness signs
// over the ciphertext hash, the snapshot id, the session nonce, and the
// owner's signing key — binding their identity to "I saw this exact opaque
// commitment at this time over this transport". The proximity claim is
// metadata only; canonical bytes plus signature are what verifiers rely on.

import Foundation
import PKECrypto

public struct WitnessAttestation: Codable, Equatable, Sendable {

    public static let typeName = "witness_attestation"

    public let type: String
    public let version: String
    public let snapshotId: String
    @Base64UrlData public var ciphertextHash: Data
    @Base64UrlData public var sessionNonce: Data
    @Base64UrlData public var ownerSigningPublicKey: Data
    @Base64UrlData public var witnessSigningPublicKey: Data
    public let witnessTimestamp: ISO8601UTCDate
    public let transport: String
    public let proximityClaim: ProximityClaim
    @Base64UrlData public var witnessSignature: Data

    public init(
        version: String,
        snapshotId: String,
        ciphertextHash: Data,
        sessionNonce: Data,
        ownerSigningPublicKey: Data,
        witnessSigningPublicKey: Data,
        witnessTimestamp: ISO8601UTCDate,
        transport: String,
        proximityClaim: ProximityClaim,
        witnessSignature: Data
    ) {
        self.type = Self.typeName
        self.version = version
        self.snapshotId = snapshotId
        self._ciphertextHash = Base64UrlData(wrappedValue: ciphertextHash)
        self._sessionNonce = Base64UrlData(wrappedValue: sessionNonce)
        self._ownerSigningPublicKey = Base64UrlData(wrappedValue: ownerSigningPublicKey)
        self._witnessSigningPublicKey = Base64UrlData(wrappedValue: witnessSigningPublicKey)
        self.witnessTimestamp = witnessTimestamp
        self.transport = transport
        self.proximityClaim = proximityClaim
        self._witnessSignature = Base64UrlData(wrappedValue: witnessSignature)
    }

    public struct ProximityClaim: Codable, Equatable, Sendable {

        public let method: String
        public let exactLocationPublic: Bool

        public init(method: String, exactLocationPublic: Bool) {
            self.method = method
            self.exactLocationPublic = exactLocationPublic
        }

        enum CodingKeys: String, CodingKey, CaseIterable {
            case method
            case exactLocationPublic = "exact_location_public"
        }

        public init(from decoder: Decoder) throws {
            try requireNoUnknownKeys(in: decoder, against: CodingKeys.self)
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.method = try container.decode(String.self, forKey: .method)
            self.exactLocationPublic =
                try container.decode(Bool.self, forKey: .exactLocationPublic)
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(method, forKey: .method)
            try container.encode(exactLocationPublic, forKey: .exactLocationPublic)
        }
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case version
        case snapshotId = "snapshot_id"
        case ciphertextHash = "ciphertext_hash"
        case sessionNonce = "session_nonce"
        case ownerSigningPublicKey = "owner_signing_public_key"
        case witnessSigningPublicKey = "witness_signing_public_key"
        case witnessTimestamp = "witness_timestamp"
        case transport
        case proximityClaim = "proximity_claim"
        case witnessSignature = "witness_signature"
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
        self._ciphertextHash = try container.decode(Base64UrlData.self, forKey: .ciphertextHash)
        self._sessionNonce = try container.decode(Base64UrlData.self, forKey: .sessionNonce)
        self._ownerSigningPublicKey = try container.decode(
            Base64UrlData.self,
            forKey: .ownerSigningPublicKey
        )
        self._witnessSigningPublicKey = try container.decode(
            Base64UrlData.self,
            forKey: .witnessSigningPublicKey
        )
        self.witnessTimestamp = try container.decode(ISO8601UTCDate.self, forKey: .witnessTimestamp)
        self.transport = try container.decode(String.self, forKey: .transport)
        self.proximityClaim = try container.decode(ProximityClaim.self, forKey: .proximityClaim)
        self._witnessSignature = try container.decode(Base64UrlData.self, forKey: .witnessSignature)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(version, forKey: .version)
        try container.encode(snapshotId, forKey: .snapshotId)
        try container.encode(_ciphertextHash, forKey: .ciphertextHash)
        try container.encode(_sessionNonce, forKey: .sessionNonce)
        try container.encode(_ownerSigningPublicKey, forKey: .ownerSigningPublicKey)
        try container.encode(_witnessSigningPublicKey, forKey: .witnessSigningPublicKey)
        try container.encode(witnessTimestamp, forKey: .witnessTimestamp)
        try container.encode(transport, forKey: .transport)
        try container.encode(proximityClaim, forKey: .proximityClaim)
        try container.encode(_witnessSignature, forKey: .witnessSignature)
    }
}
