// Deterministic canonical-JSON encoder for signed payloads (HLAM-3 / HLAM-7).
// Swift mirror of the backend `pke_backend.crypto.canonicalize` module; see
// `context/16_canonical_encoding.md` §Canonical JSON for the locked v0.1 rules:
//   - keys sorted by UTF-8 byte sequence at every level,
//   - minified separators (`,` and `:`) with no whitespace,
//   - non-ASCII characters emitted as raw UTF-8 (no `\uXXXX` escapes),
//   - NaN / Infinity rejected,
//   - no trailing newline,
//   - recursion depth bounded at `MAX_DEPTH = 64`.

import Foundation

public enum CanonicalJSON {

    public static let maxDepth = 64

    public static func encode(_ value: JSONValue) throws -> Data {
        try checkDepth(value, depth: 1)
        var buffer = Data()
        try encodeValue(value, into: &buffer)
        return buffer
    }

    // MARK: - Depth bound

    private static func checkDepth(_ value: JSONValue, depth: Int) throws {
        if depth > Self.maxDepth {
            throw CryptoError.canonicalEncoding(reason: "nesting exceeds MAX_DEPTH=\(Self.maxDepth)")
        }
        switch value {
        case .object(let pairs):
            for (_, child) in pairs {
                try Self.checkDepth(child, depth: depth + 1)
            }
        case .array(let items):
            for child in items {
                try Self.checkDepth(child, depth: depth + 1)
            }
        default:
            return
        }
    }

    // MARK: - Encoding

    private static func encodeValue(_ value: JSONValue, into buffer: inout Data) throws {
        switch value {
        case .null:
            buffer.append(contentsOf: [0x6E, 0x75, 0x6C, 0x6C])
        case .bool(let flag):
            if flag {
                buffer.append(contentsOf: [0x74, 0x72, 0x75, 0x65])
            } else {
                buffer.append(contentsOf: [0x66, 0x61, 0x6C, 0x73, 0x65])
            }
        case .int(let integer):
            buffer.append(contentsOf: Array(String(integer).utf8))
        case .double(let double):
            try Self.encodeDouble(double, into: &buffer)
        case .string(let string):
            Self.encodeString(string, into: &buffer)
        case .array(let items):
            try Self.encodeArray(items, into: &buffer)
        case .object(let pairs):
            try Self.encodeObject(pairs, into: &buffer)
        }
    }

    private static func encodeArray(_ items: [JSONValue], into buffer: inout Data) throws {
        buffer.append(0x5B)
        for (index, item) in items.enumerated() {
            if index > 0 {
                buffer.append(0x2C)
            }
            try Self.encodeValue(item, into: &buffer)
        }
        buffer.append(0x5D)
    }

    private static func encodeObject(_ pairs: [(String, JSONValue)], into buffer: inout Data) throws {
        // Sort by UTF-8 byte sequence. Swift's `String <` operator compares by
        // Unicode scalar order; for any pair of well-formed UTF-8 strings the
        // scalar order equals the byte order because UTF-8 is designed to
        // preserve code-point ordering across multi-byte sequences.
        let sorted = pairs.sorted { lhs, rhs in
            lhs.0 < rhs.0
        }
        buffer.append(0x7B)
        for (index, pair) in sorted.enumerated() {
            if index > 0 {
                buffer.append(0x2C)
            }
            Self.encodeString(pair.0, into: &buffer)
            buffer.append(0x3A)
            try Self.encodeValue(pair.1, into: &buffer)
        }
        buffer.append(0x7D)
    }

    private static func encodeString(_ string: String, into buffer: inout Data) {
        buffer.append(0x22)
        for scalar in string.unicodeScalars {
            switch scalar.value {
            case 0x22:
                buffer.append(contentsOf: [0x5C, 0x22])
            case 0x5C:
                buffer.append(contentsOf: [0x5C, 0x5C])
            case 0x08:
                buffer.append(contentsOf: [0x5C, 0x62])
            case 0x0C:
                buffer.append(contentsOf: [0x5C, 0x66])
            case 0x0A:
                buffer.append(contentsOf: [0x5C, 0x6E])
            case 0x0D:
                buffer.append(contentsOf: [0x5C, 0x72])
            case 0x09:
                buffer.append(contentsOf: [0x5C, 0x74])
            case 0x00...0x1F:
                let hex = String(format: "%04x", scalar.value)
                buffer.append(contentsOf: [0x5C, 0x75])
                buffer.append(contentsOf: Array(hex.utf8))
            default:
                // Raw UTF-8 — Python's ensure_ascii=False parity.
                let utf8 = String(scalar).utf8
                buffer.append(contentsOf: utf8)
            }
        }
        buffer.append(0x22)
    }

    // MARK: - Float caveat
    //
    // No current fixture exercises floating-point output, and Python's
    // `json.dumps` and Swift's `String(Double)` use different shortest-form
    // algorithms (Python's `repr` vs. Grisu/Ryu). Strict byte-parity with the
    // backend is only guaranteed for the int/string/bool/null/array/object
    // subset; floats are accepted but their textual form is not contractually
    // pinned across runtimes.
    private static func encodeDouble(_ double: Double, into buffer: inout Data) throws {
        if !double.isFinite {
            throw CryptoError.canonicalEncoding(reason: "non-finite number")
        }
        buffer.append(contentsOf: Array(String(double).utf8))
    }
}
