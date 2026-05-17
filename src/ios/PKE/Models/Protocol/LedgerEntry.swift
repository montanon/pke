// Swift mirror of `pke_backend.protocol.LedgerEntry`. Each entry hashes the
// preceding one (`previous_entry_hash`) and a domain-separated payload
// (`payload_hash`) into `entry_hash`; the resulting chain is the verifiable
// custody record. `event_type` is enumerated to the 5 protocol events to
// keep typos out of the wire and to make exhaustive switches possible.

import Foundation
import PKECrypto

public enum LedgerEventType: String, Codable, CaseIterable, Sendable {
    case snapshotCommitted = "SNAPSHOT_COMMITTED"
    case witnessAttested = "WITNESS_ATTESTED"
    case keyGranted = "KEY_GRANTED"
    case reported = "REPORTED"
    case frozen = "FROZEN"
}

public struct LedgerEntry: Codable, Equatable, Sendable {

    public static let typeName = "ledger_entry"

    public let type: String
    public let version: String
    public let ledgerEntryId: String
    public let eventType: LedgerEventType
    public let snapshotId: String
    @Base64UrlData public var payloadHash: Data
    @Base64UrlData public var previousEntryHash: Data
    public let entryTimestamp: ISO8601UTCDate
    @Base64UrlData public var entryHash: Data

    public init(
        version: String,
        ledgerEntryId: String,
        eventType: LedgerEventType,
        snapshotId: String,
        payloadHash: Data,
        previousEntryHash: Data,
        entryTimestamp: ISO8601UTCDate,
        entryHash: Data
    ) {
        self.type = Self.typeName
        self.version = version
        self.ledgerEntryId = ledgerEntryId
        self.eventType = eventType
        self.snapshotId = snapshotId
        self._payloadHash = Base64UrlData(wrappedValue: payloadHash)
        self._previousEntryHash = Base64UrlData(wrappedValue: previousEntryHash)
        self.entryTimestamp = entryTimestamp
        self._entryHash = Base64UrlData(wrappedValue: entryHash)
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case version
        case ledgerEntryId = "ledger_entry_id"
        case eventType = "event_type"
        case snapshotId = "snapshot_id"
        case payloadHash = "payload_hash"
        case previousEntryHash = "previous_entry_hash"
        case entryTimestamp = "entry_timestamp"
        case entryHash = "entry_hash"
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
        self.ledgerEntryId = try container.decode(String.self, forKey: .ledgerEntryId)
        self.eventType = try container.decode(LedgerEventType.self, forKey: .eventType)
        self.snapshotId = try container.decode(String.self, forKey: .snapshotId)
        self._payloadHash = try container.decode(Base64UrlData.self, forKey: .payloadHash)
        self._previousEntryHash = try container.decode(Base64UrlData.self, forKey: .previousEntryHash)
        self.entryTimestamp = try container.decode(ISO8601UTCDate.self, forKey: .entryTimestamp)
        self._entryHash = try container.decode(Base64UrlData.self, forKey: .entryHash)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(version, forKey: .version)
        try container.encode(ledgerEntryId, forKey: .ledgerEntryId)
        try container.encode(eventType, forKey: .eventType)
        try container.encode(snapshotId, forKey: .snapshotId)
        try container.encode(_payloadHash, forKey: .payloadHash)
        try container.encode(_previousEntryHash, forKey: .previousEntryHash)
        try container.encode(entryTimestamp, forKey: .entryTimestamp)
        try container.encode(_entryHash, forKey: .entryHash)
    }
}
