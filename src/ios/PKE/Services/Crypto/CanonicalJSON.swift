import Foundation

public enum CanonicalJSON {
    public static func encode(_ value: JSONValue) -> Data {
        var bytes: [UInt8] = []
        appendValue(value, into: &bytes)
        return Data(bytes)
    }

    private static func appendValue(_ value: JSONValue, into bytes: inout [UInt8]) {
        switch value {
        case .null:
            bytes.append(contentsOf: literalNull)
        case .bool(let flag):
            bytes.append(contentsOf: flag ? literalTrue : literalFalse)
        case .integer(let int):
            bytes.append(contentsOf: Array(String(int).utf8))
        case .string(let str):
            appendString(str, into: &bytes)
        case .array(let items):
            appendArray(items, into: &bytes)
        case .object(let entries):
            appendObject(entries, into: &bytes)
        }
    }

    private static func appendArray(_ items: [JSONValue], into bytes: inout [UInt8]) {
        bytes.append(0x5B) // [
        for (index, item) in items.enumerated() {
            if index > 0 { bytes.append(0x2C) }
            appendValue(item, into: &bytes)
        }
        bytes.append(0x5D) // ]
    }

    private static func appendObject(_ entries: [String: JSONValue], into bytes: inout [UInt8]) {
        bytes.append(0x7B) // {
        let sortedKeys = entries.keys.sorted { lhs, rhs in
            lhs.utf8.lexicographicallyPrecedes(rhs.utf8)
        }
        for (index, key) in sortedKeys.enumerated() {
            if index > 0 { bytes.append(0x2C) }
            appendString(key, into: &bytes)
            bytes.append(0x3A) // :
            // sortedKeys came from entries.keys, so the subscript always hits.
            if let child = entries[key] {
                appendValue(child, into: &bytes)
            }
        }
        bytes.append(0x7D) // }
    }

    private static func appendString(_ str: String, into bytes: inout [UInt8]) {
        bytes.append(0x22) // "
        for byte in str.utf8 {
            appendStringByte(byte, into: &bytes)
        }
        bytes.append(0x22)
    }

    private static func appendStringByte(_ byte: UInt8, into bytes: inout [UInt8]) {
        switch byte {
        case 0x22:
            bytes.append(contentsOf: [0x5C, 0x22])
        case 0x5C:
            bytes.append(contentsOf: [0x5C, 0x5C])
        case 0x08:
            bytes.append(contentsOf: [0x5C, 0x62])
        case 0x09:
            bytes.append(contentsOf: [0x5C, 0x74])
        case 0x0A:
            bytes.append(contentsOf: [0x5C, 0x6E])
        case 0x0C:
            bytes.append(contentsOf: [0x5C, 0x66])
        case 0x0D:
            bytes.append(contentsOf: [0x5C, 0x72])
        case 0x00...0x1F:
            appendUnicodeEscape(byte, into: &bytes)
        default:
            bytes.append(byte)
        }
    }

    private static func appendUnicodeEscape(_ byte: UInt8, into bytes: inout [UInt8]) {
        // \u00XX — only reachable for control bytes (0x00..0x1F) outside short escapes.
        bytes.append(contentsOf: [0x5C, 0x75, 0x30, 0x30])
        bytes.append(hexDigit(byte >> 4))
        bytes.append(hexDigit(byte & 0x0F))
    }

    private static func hexDigit(_ nibble: UInt8) -> UInt8 {
        // Lowercase to match Python json.dumps and ensure a single canonical form.
        nibble < 10 ? (0x30 + nibble) : (0x61 + nibble - 10)
    }

    private static let literalNull: [UInt8] = [0x6E, 0x75, 0x6C, 0x6C]
    private static let literalTrue: [UInt8] = [0x74, 0x72, 0x75, 0x65]
    private static let literalFalse: [UInt8] = [0x66, 0x61, 0x6C, 0x73, 0x65]
}
