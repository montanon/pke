// Strict ISO 8601 UTC datetime wrapper used by every protocol payload that
// carries a wall-clock timestamp. The on-the-wire shape is the canonical
// 20-character form `YYYY-MM-DDTHH:MM:SSZ`: no fractional seconds, no
// timezone offset other than `Z`, no naive (offset-less) datetimes.
//
// Decode runs the input through a strict `DateFormatter` and additionally
// requires that re-formatting the parsed date reproduces the original string
// byte-for-byte — this rejects partial matches such as `2026-5-15T00:00:00Z`
// that `DateFormatter` would otherwise tolerate via lenient day/month padding
// on some platforms. Encode emits the same canonical 20-character form, so
// round-trips through `CanonicalJSON` preserve timestamp bytes exactly.

import Foundation

public struct ISO8601UTCDate: Codable, Equatable, Hashable, Sendable {

    public let date: Date

    public init(_ date: Date) {
        self.date = date
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let parsed = Self.formatter.date(from: raw),
              Self.formatter.string(from: parsed) == raw else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription:
                    "expected strict UTC datetime YYYY-MM-DDTHH:MM:SSZ, got \"\(raw)\""
            )
        }
        self.date = parsed
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(Self.formatter.string(from: date))
    }

    public var iso8601String: String {
        Self.formatter.string(from: date)
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return formatter
    }()
}
