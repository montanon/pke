// Strongly typed JSON value used by the canonical-encoding pipeline (HLAM-7).
// Mirrors the backend `pke_backend.crypto.types.JsonValue` shape and ships a
// strict RFC 8259 decoder that:
//   - preserves object key order at decode time (canonical encoder re-sorts);
//   - rejects duplicate keys at the same level (JSONSerialization silently
//     overwrites, which would mask a canonical-encoding violation);
//   - rejects NaN / Infinity / leading-zero numeric forms;
//   - distinguishes integers fitting in `Int64` from floating-point values.
// All errors surface as `CryptoError.canonicalEncoding(reason:)`.

import Foundation

public indirect enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([Self])
    case object([(String, Self)])

    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null):
            return true
        case let (.bool(left), .bool(right)):
            return left == right
        case let (.int(left), .int(right)):
            return left == right
        case let (.double(left), .double(right)):
            return left.bitPattern == right.bitPattern
        case let (.string(left), .string(right)):
            return left == right
        case let (.array(left), .array(right)):
            return left == right
        case let (.object(left), .object(right)):
            guard left.count == right.count else { return false }
            for (leftPair, rightPair) in zip(left, right) where leftPair.0 != rightPair.0 || leftPair.1 != rightPair.1 {
                return false
            }
            return true
        default:
            return false
        }
    }

    /// Parse `data` as strict RFC 8259 JSON. See file header for rejection rules.
    public static func decode(_ data: Data) throws -> Self {
        var parser = JSONParser(bytes: Array(data))
        let value = try parser.parseValue()
        parser.skipWhitespace()
        if !parser.isAtEnd {
            throw CryptoError.canonicalEncoding(reason: "trailing data after value")
        }
        return value
    }
}

// MARK: - Recursive-descent parser

// swiftlint:disable type_body_length

private struct JSONParser {
    let bytes: [UInt8]
    var offset: Int = 0

    var isAtEnd: Bool { offset >= bytes.count }

    mutating func parseValue() throws -> JSONValue {
        skipWhitespace()
        guard !isAtEnd else {
            throw CryptoError.canonicalEncoding(reason: "unexpected end of input")
        }
        let byte = bytes[offset]
        switch byte {
        case 0x7B: // '{'
            return try parseObject()
        case 0x5B: // '['
            return try parseArray()
        case 0x22: // '"'
            return .string(try parseString())
        case 0x74, 0x66: // 't' / 'f'
            return .bool(try parseBool())
        case 0x6E: // 'n'
            try parseNull()
            return .null
        case 0x2D, 0x30...0x39: // '-' or digit
            return try parseNumber()
        default:
            throw CryptoError.canonicalEncoding(reason: "unexpected byte at offset \(offset)")
        }
    }

    mutating func parseObject() throws -> JSONValue {
        offset += 1 // consume '{'
        var pairs: [(String, JSONValue)] = []
        var seenKeys: Set<String> = []
        skipWhitespace()
        if !isAtEnd, bytes[offset] == 0x7D {
            offset += 1
            return .object(pairs)
        }
        while true {
            skipWhitespace()
            guard !isAtEnd, bytes[offset] == 0x22 else {
                throw CryptoError.canonicalEncoding(reason: "expected string key at offset \(offset)")
            }
            let key = try parseString()
            if seenKeys.contains(key) {
                throw CryptoError.canonicalEncoding(reason: "duplicate key")
            }
            seenKeys.insert(key)
            skipWhitespace()
            guard !isAtEnd, bytes[offset] == 0x3A else {
                throw CryptoError.canonicalEncoding(reason: "expected ':' at offset \(offset)")
            }
            offset += 1
            let value = try parseValue()
            pairs.append((key, value))
            skipWhitespace()
            guard !isAtEnd else {
                throw CryptoError.canonicalEncoding(reason: "unterminated object")
            }
            switch bytes[offset] {
            case 0x2C:
                offset += 1
            case 0x7D:
                offset += 1
                return .object(pairs)
            default:
                throw CryptoError.canonicalEncoding(reason: "expected ',' or '}' at offset \(offset)")
            }
        }
    }

    mutating func parseArray() throws -> JSONValue {
        offset += 1 // consume '['
        var items: [JSONValue] = []
        skipWhitespace()
        if !isAtEnd, bytes[offset] == 0x5D {
            offset += 1
            return .array(items)
        }
        while true {
            let value = try parseValue()
            items.append(value)
            skipWhitespace()
            guard !isAtEnd else {
                throw CryptoError.canonicalEncoding(reason: "unterminated array")
            }
            switch bytes[offset] {
            case 0x2C:
                offset += 1
            case 0x5D:
                offset += 1
                return .array(items)
            default:
                throw CryptoError.canonicalEncoding(reason: "expected ',' or ']' at offset \(offset)")
            }
        }
    }

    mutating func parseBool() throws -> Bool {
        if matchLiteral([0x74, 0x72, 0x75, 0x65]) {
            return true
        }
        if matchLiteral([0x66, 0x61, 0x6C, 0x73, 0x65]) {
            return false
        }
        throw CryptoError.canonicalEncoding(reason: "invalid literal at offset \(offset)")
    }

    mutating func parseNull() throws {
        if !matchLiteral([0x6E, 0x75, 0x6C, 0x6C]) {
            throw CryptoError.canonicalEncoding(reason: "invalid literal at offset \(offset)")
        }
    }

    mutating func matchLiteral(_ literal: [UInt8]) -> Bool {
        let end = offset + literal.count
        guard end <= bytes.count else { return false }
        for index in 0..<literal.count where bytes[offset + index] != literal[index] {
            return false
        }
        offset = end
        return true
    }

    mutating func parseNumber() throws -> JSONValue {
        let start = offset
        if !isAtEnd, bytes[offset] == 0x2D {
            offset += 1
        }
        try parseIntegerPart(start: start)
        var isFloat = try parseFractionalPart(start: start)
        if try parseExponentPart(start: start) {
            isFloat = true
        }
        let slice = bytes[start..<offset]
        guard let literal = String(bytes: slice, encoding: .ascii) else {
            throw CryptoError.canonicalEncoding(reason: "invalid number at offset \(start)")
        }
        if !isFloat, let integer = Int64(literal) {
            return .int(integer)
        }
        guard let double = Double(literal), double.isFinite else {
            throw CryptoError.canonicalEncoding(reason: "non-finite number")
        }
        return .double(double)
    }

    private mutating func parseIntegerPart(start: Int) throws {
        guard !isAtEnd, isDigit(bytes[offset]) else {
            throw CryptoError.canonicalEncoding(reason: "invalid number at offset \(start)")
        }
        if bytes[offset] == 0x30 {
            offset += 1
            return
        }
        while !isAtEnd, isDigit(bytes[offset]) {
            offset += 1
        }
    }

    private mutating func parseFractionalPart(start: Int) throws -> Bool {
        guard !isAtEnd, bytes[offset] == 0x2E else { return false }
        offset += 1
        guard !isAtEnd, isDigit(bytes[offset]) else {
            throw CryptoError.canonicalEncoding(reason: "invalid number at offset \(start)")
        }
        while !isAtEnd, isDigit(bytes[offset]) {
            offset += 1
        }
        return true
    }

    private mutating func parseExponentPart(start: Int) throws -> Bool {
        guard !isAtEnd, bytes[offset] == 0x65 || bytes[offset] == 0x45 else { return false }
        offset += 1
        if !isAtEnd, bytes[offset] == 0x2B || bytes[offset] == 0x2D {
            offset += 1
        }
        guard !isAtEnd, isDigit(bytes[offset]) else {
            throw CryptoError.canonicalEncoding(reason: "invalid number at offset \(start)")
        }
        while !isAtEnd, isDigit(bytes[offset]) {
            offset += 1
        }
        return true
    }

    mutating func parseString() throws -> String {
        // Caller verified the opening quote.
        offset += 1
        var scalars: [Unicode.Scalar] = []
        while !isAtEnd {
            let byte = bytes[offset]
            if byte == 0x22 {
                offset += 1
                var out = ""
                out.unicodeScalars.reserveCapacity(scalars.count)
                for scalar in scalars {
                    out.unicodeScalars.append(scalar)
                }
                return out
            }
            if byte == 0x5C {
                offset += 1
                try decodeEscape(into: &scalars)
                continue
            }
            if byte < 0x20 {
                throw CryptoError.canonicalEncoding(reason: "unescaped control byte at offset \(offset)")
            }
            // UTF-8 multi-byte sequences: validate by decoding the next code point.
            let scalar = try decodeUTF8Scalar()
            scalars.append(scalar)
        }
        throw CryptoError.canonicalEncoding(reason: "unterminated string")
    }

    mutating func decodeEscape(into scalars: inout [Unicode.Scalar]) throws {
        guard !isAtEnd else {
            throw CryptoError.canonicalEncoding(reason: "dangling escape at offset \(offset)")
        }
        let byte = bytes[offset]
        offset += 1
        if let simple = Self.simpleEscapeScalar(for: byte) {
            scalars.append(simple)
            return
        }
        if byte == 0x75 {
            scalars.append(try decodeUnicodeEscape())
            return
        }
        throw CryptoError.canonicalEncoding(reason: "invalid escape at offset \(offset)")
    }

    private static func simpleEscapeScalar(for byte: UInt8) -> Unicode.Scalar? {
        switch byte {
        case 0x22: return Unicode.Scalar(0x22)
        case 0x5C: return Unicode.Scalar(0x5C)
        case 0x2F: return Unicode.Scalar(0x2F)
        case 0x62: return Unicode.Scalar(0x08)
        case 0x66: return Unicode.Scalar(0x0C)
        case 0x6E: return Unicode.Scalar(0x0A)
        case 0x72: return Unicode.Scalar(0x0D)
        case 0x74: return Unicode.Scalar(0x09)
        default: return nil
        }
    }

    mutating func decodeUnicodeEscape() throws -> Unicode.Scalar {
        let code = try readHex4()
        if (0xD800...0xDBFF).contains(code) {
            return try decodeSurrogatePair(high: code)
        }
        if (0xDC00...0xDFFF).contains(code) {
            throw CryptoError.canonicalEncoding(reason: "lone low surrogate at offset \(offset)")
        }
        guard let scalar = Unicode.Scalar(code) else {
            throw CryptoError.canonicalEncoding(reason: "invalid \\u escape at offset \(offset)")
        }
        return scalar
    }

    mutating func decodeSurrogatePair(high: UInt32) throws -> Unicode.Scalar {
        guard offset + 1 < bytes.count, bytes[offset] == 0x5C, bytes[offset + 1] == 0x75 else {
            throw CryptoError.canonicalEncoding(reason: "lone high surrogate at offset \(offset)")
        }
        offset += 2
        let low = try readHex4()
        guard (0xDC00...0xDFFF).contains(low) else {
            throw CryptoError.canonicalEncoding(reason: "invalid low surrogate at offset \(offset)")
        }
        let combined = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
        guard let scalar = Unicode.Scalar(combined) else {
            throw CryptoError.canonicalEncoding(reason: "invalid surrogate pair at offset \(offset)")
        }
        return scalar
    }

    mutating func readHex4() throws -> UInt32 {
        guard offset + 4 <= bytes.count else {
            throw CryptoError.canonicalEncoding(reason: "truncated \\u escape at offset \(offset)")
        }
        var value: UInt32 = 0
        for _ in 0..<4 {
            let nibble: UInt32
            let byte = bytes[offset]
            switch byte {
            case 0x30...0x39: nibble = UInt32(byte - 0x30)
            case 0x41...0x46: nibble = UInt32(byte - 0x41 + 10)
            case 0x61...0x66: nibble = UInt32(byte - 0x61 + 10)
            default:
                throw CryptoError.canonicalEncoding(reason: "non-hex digit in \\u escape at offset \(offset)")
            }
            value = (value << 4) | nibble
            offset += 1
        }
        return value
    }

    mutating func decodeUTF8Scalar() throws -> Unicode.Scalar {
        let first = bytes[offset]
        let width: Int
        var value: UInt32
        switch first {
        case 0x00...0x7F:
            offset += 1
            // Safe: ASCII range is always a valid Unicode scalar.
            return Unicode.Scalar(first)
        case 0xC2...0xDF:
            width = 2
            value = UInt32(first & 0x1F)
        case 0xE0...0xEF:
            width = 3
            value = UInt32(first & 0x0F)
        case 0xF0...0xF4:
            width = 4
            value = UInt32(first & 0x07)
        default:
            throw CryptoError.canonicalEncoding(reason: "invalid utf-8 lead byte at offset \(offset)")
        }
        guard offset + width <= bytes.count else {
            throw CryptoError.canonicalEncoding(reason: "truncated utf-8 sequence at offset \(offset)")
        }
        for index in 1..<width {
            let continuation = bytes[offset + index]
            guard (continuation & 0xC0) == 0x80 else {
                throw CryptoError.canonicalEncoding(reason: "invalid utf-8 continuation at offset \(offset + index)")
            }
            value = (value << 6) | UInt32(continuation & 0x3F)
        }
        offset += width
        guard let scalar = Unicode.Scalar(value) else {
            throw CryptoError.canonicalEncoding(reason: "invalid unicode scalar at offset \(offset)")
        }
        // Reject overlong encodings and surrogate range.
        if (0xD800...0xDFFF).contains(value) {
            throw CryptoError.canonicalEncoding(reason: "utf-8 encoded surrogate at offset \(offset)")
        }
        return scalar
    }

    mutating func skipWhitespace() {
        while !isAtEnd {
            switch bytes[offset] {
            case 0x20, 0x09, 0x0A, 0x0D:
                offset += 1
            default:
                return
            }
        }
    }

    private func isDigit(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte)
    }
}

// swiftlint:enable type_body_length
