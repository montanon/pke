// Swift mirror of `pke_backend.protocol.KeyGrant`. The owner wraps the
// snapshot data-encryption key to a recipient's encryption identity via
// `wrapping_algorithm` (e.g. `ecdhp256+aesgcm256`) and signs the grant.
// The backend never sees plaintext snapshot keys — only opaque wrapped
// blobs that route to the named recipient.

import Foundation
import PKECrypto

public struct KeyGrant: Codable, Equatable, Sendable {

    public static let typeName = "key_grant"

    public let type: String
    public let version: String
    public let grantId: String
    public let snapshotId: String
    @Base64UrlData public var recipientEncryptionPublicKey: Data
    @Base64UrlData public var wrappedSnapshotKey: Data
    public let wrappingAlgorithm: String
    @Base64UrlData public var grantedBySigningPublicKey: Data
    public let grantTimestamp: ISO8601UTCDate
    @Base64UrlData public var grantSignature: Data

    public init(
        version: String,
        grantId: String,
        snapshotId: String,
        recipientEncryptionPublicKey: Data,
        wrappedSnapshotKey: Data,
        wrappingAlgorithm: String,
        grantedBySigningPublicKey: Data,
        grantTimestamp: ISO8601UTCDate,
        grantSignature: Data
    ) {
        self.type = Self.typeName
        self.version = version
        self.grantId = grantId
        self.snapshotId = snapshotId
        self._recipientEncryptionPublicKey =
            Base64UrlData(wrappedValue: recipientEncryptionPublicKey)
        self._wrappedSnapshotKey = Base64UrlData(wrappedValue: wrappedSnapshotKey)
        self.wrappingAlgorithm = wrappingAlgorithm
        self._grantedBySigningPublicKey =
            Base64UrlData(wrappedValue: grantedBySigningPublicKey)
        self.grantTimestamp = grantTimestamp
        self._grantSignature = Base64UrlData(wrappedValue: grantSignature)
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case version
        case grantId = "grant_id"
        case snapshotId = "snapshot_id"
        case recipientEncryptionPublicKey = "recipient_encryption_public_key"
        case wrappedSnapshotKey = "wrapped_snapshot_key"
        case wrappingAlgorithm = "wrapping_algorithm"
        case grantedBySigningPublicKey = "granted_by_signing_public_key"
        case grantTimestamp = "grant_timestamp"
        case grantSignature = "grant_signature"
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
        self.grantId = try container.decode(String.self, forKey: .grantId)
        self.snapshotId = try container.decode(String.self, forKey: .snapshotId)
        self._recipientEncryptionPublicKey = try container.decode(
            Base64UrlData.self,
            forKey: .recipientEncryptionPublicKey
        )
        self._wrappedSnapshotKey = try container.decode(
            Base64UrlData.self,
            forKey: .wrappedSnapshotKey
        )
        self.wrappingAlgorithm = try container.decode(String.self, forKey: .wrappingAlgorithm)
        self._grantedBySigningPublicKey = try container.decode(
            Base64UrlData.self,
            forKey: .grantedBySigningPublicKey
        )
        self.grantTimestamp = try container.decode(ISO8601UTCDate.self, forKey: .grantTimestamp)
        self._grantSignature = try container.decode(Base64UrlData.self, forKey: .grantSignature)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(version, forKey: .version)
        try container.encode(grantId, forKey: .grantId)
        try container.encode(snapshotId, forKey: .snapshotId)
        try container.encode(_recipientEncryptionPublicKey, forKey: .recipientEncryptionPublicKey)
        try container.encode(_wrappedSnapshotKey, forKey: .wrappedSnapshotKey)
        try container.encode(wrappingAlgorithm, forKey: .wrappingAlgorithm)
        try container.encode(_grantedBySigningPublicKey, forKey: .grantedBySigningPublicKey)
        try container.encode(grantTimestamp, forKey: .grantTimestamp)
        try container.encode(_grantSignature, forKey: .grantSignature)
    }
}
