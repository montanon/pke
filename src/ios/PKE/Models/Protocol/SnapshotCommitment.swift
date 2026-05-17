// Swift mirror of `pke_backend.protocol.SnapshotCommitment`. Carries the
// owner-signed commitment to a captured snapshot: the ciphertext hash, the
// owner's signing/encryption identities, capture time, declared metadata
// policy, session nonce, and the detached signature over the payload.
//
// Decode is strict: unknown keys are rejected (mirrors Pydantic
// `extra='forbid'`) and the `type` discriminator must equal
// `snapshot_commitment`. Binary fields go through `@Base64UrlData`; the
// timestamp goes through `ISO8601UTCDate`. Both sides of the wire share the
// same canonical-bytes fixture under `src/shared/test_vectors/protocol/`.

import Foundation
import PKECrypto

public struct SnapshotCommitment: Codable, Equatable, Sendable {

    public static let typeName = "snapshot_commitment"

    public let type: String
    public let version: String
    public let snapshotId: String
    @Base64UrlData public var ciphertextHash: Data
    @Base64UrlData public var ownerSigningPublicKey: Data
    @Base64UrlData public var ownerEncryptionPublicKey: Data
    public let captureTimestamp: ISO8601UTCDate
    public let metadataPolicy: MetadataPolicy
    @Base64UrlData public var sessionNonce: Data
    @Base64UrlData public var ownerSignature: Data

    public init(
        version: String,
        snapshotId: String,
        ciphertextHash: Data,
        ownerSigningPublicKey: Data,
        ownerEncryptionPublicKey: Data,
        captureTimestamp: ISO8601UTCDate,
        metadataPolicy: MetadataPolicy,
        sessionNonce: Data,
        ownerSignature: Data
    ) {
        self.type = Self.typeName
        self.version = version
        self.snapshotId = snapshotId
        self._ciphertextHash = Base64UrlData(wrappedValue: ciphertextHash)
        self._ownerSigningPublicKey = Base64UrlData(wrappedValue: ownerSigningPublicKey)
        self._ownerEncryptionPublicKey = Base64UrlData(wrappedValue: ownerEncryptionPublicKey)
        self.captureTimestamp = captureTimestamp
        self.metadataPolicy = metadataPolicy
        self._sessionNonce = Base64UrlData(wrappedValue: sessionNonce)
        self._ownerSignature = Base64UrlData(wrappedValue: ownerSignature)
    }

    public struct MetadataPolicy: Codable, Equatable, Sendable {

        public let locationPublic: Bool
        public let locationPrecision: String?
        public let mediaType: String

        public init(
            locationPublic: Bool,
            locationPrecision: String?,
            mediaType: String
        ) {
            self.locationPublic = locationPublic
            self.locationPrecision = locationPrecision
            self.mediaType = mediaType
        }

        enum CodingKeys: String, CodingKey, CaseIterable {
            case locationPublic = "location_public"
            case locationPrecision = "location_precision"
            case mediaType = "media_type"
        }

        public init(from decoder: Decoder) throws {
            try requireNoUnknownKeys(in: decoder, against: CodingKeys.self)
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.locationPublic = try container.decode(Bool.self, forKey: .locationPublic)
            self.locationPrecision = try container.decodeIfPresent(String.self, forKey: .locationPrecision)
            self.mediaType = try container.decode(String.self, forKey: .mediaType)
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(locationPublic, forKey: .locationPublic)
            try container.encodeIfPresent(locationPrecision, forKey: .locationPrecision)
            try container.encode(mediaType, forKey: .mediaType)
        }
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case version
        case snapshotId = "snapshot_id"
        case ciphertextHash = "ciphertext_hash"
        case ownerSigningPublicKey = "owner_signing_public_key"
        case ownerEncryptionPublicKey = "owner_encryption_public_key"
        case captureTimestamp = "capture_timestamp"
        case metadataPolicy = "metadata_policy"
        case sessionNonce = "session_nonce"
        case ownerSignature = "owner_signature"
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
        self._ownerSigningPublicKey = try container.decode(
            Base64UrlData.self,
            forKey: .ownerSigningPublicKey
        )
        self._ownerEncryptionPublicKey = try container.decode(
            Base64UrlData.self,
            forKey: .ownerEncryptionPublicKey
        )
        self.captureTimestamp = try container.decode(ISO8601UTCDate.self, forKey: .captureTimestamp)
        self.metadataPolicy = try container.decode(MetadataPolicy.self, forKey: .metadataPolicy)
        self._sessionNonce = try container.decode(Base64UrlData.self, forKey: .sessionNonce)
        self._ownerSignature = try container.decode(Base64UrlData.self, forKey: .ownerSignature)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(version, forKey: .version)
        try container.encode(snapshotId, forKey: .snapshotId)
        try container.encode(_ciphertextHash, forKey: .ciphertextHash)
        try container.encode(_ownerSigningPublicKey, forKey: .ownerSigningPublicKey)
        try container.encode(_ownerEncryptionPublicKey, forKey: .ownerEncryptionPublicKey)
        try container.encode(captureTimestamp, forKey: .captureTimestamp)
        try container.encode(metadataPolicy, forKey: .metadataPolicy)
        try container.encode(_sessionNonce, forKey: .sessionNonce)
        try container.encode(_ownerSignature, forKey: .ownerSignature)
    }
}
