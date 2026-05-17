import XCTest
@testable import PKECrypto

final class CanonicalJSONTests: XCTestCase {
    func testNull() {
        XCTAssertEqual(encodeToString(.null), "null")
    }

    func testBools() {
        XCTAssertEqual(encodeToString(.bool(true)), "true")
        XCTAssertEqual(encodeToString(.bool(false)), "false")
    }

    func testEmptyContainers() {
        XCTAssertEqual(encodeToString(.object([:])), "{}")
        XCTAssertEqual(encodeToString(.array([])), "[]")
    }

    func testIntegerBoundaries() {
        XCTAssertEqual(encodeToString(.integer(0)), "0")
        XCTAssertEqual(encodeToString(.integer(1)), "1")
        XCTAssertEqual(encodeToString(.integer(-1)), "-1")
        XCTAssertEqual(encodeToString(.integer(Int64.max)), "9223372036854775807")
        XCTAssertEqual(encodeToString(.integer(Int64.min)), "-9223372036854775808")
    }

    func testObjectKeySort() {
        let input: JSONValue = .object([
            "b": .integer(1),
            "a": .integer(2)
        ])
        XCTAssertEqual(encodeToString(input), "{\"a\":2,\"b\":1}")
    }

    func testRecursiveKeySort() {
        let nested: JSONValue = .array([
            .object([
                "z": .integer(1),
                "a": .object([
                    "y": .integer(2),
                    "b": .integer(3)
                ])
            ])
        ])
        XCTAssertEqual(
            encodeToString(nested),
            "[{\"a\":{\"b\":3,\"y\":2},\"z\":1}]"
        )
    }

    func testUTF8StringEmittedRaw() {
        let data = CanonicalJSON.encode(.string("héllo"))
        // "héllo" is 5 chars / 6 UTF-8 bytes; with surrounding quotes => 8 bytes.
        let expected = Data([0x22, 0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F, 0x22])
        XCTAssertEqual(data, expected)
        // Sanity: encoder MUST NOT emit \uXXXX escapes for non-ASCII.
        let asString = String(decoding: data, as: UTF8.self)
        XCTAssertFalse(asString.contains("\\u"))
    }

    func testStringEscapes() {
        let input: JSONValue = .string("a\\b\"c\nd\te\u{0001}f")
        // Expected: "a\\b\"c\nd\tef"
        XCTAssertEqual(
            encodeToString(input),
            "\"a\\\\b\\\"c\\nd\\te\\u0001f\""
        )
    }

    func testForwardSlashNotEscaped() {
        XCTAssertEqual(encodeToString(.string("a/b")), "\"a/b\"")
    }

    func testNoTrailingNewline() {
        let objectData = CanonicalJSON.encode(.object(["a": .integer(1)]))
        XCTAssertEqual(objectData.last, 0x7D) // }
        let arrayData = CanonicalJSON.encode(.array([.integer(1)]))
        XCTAssertEqual(arrayData.last, 0x5D) // ]
    }

    func testUTF8ByteOrderSortDivergesFromSwiftStringOrder() {
        // Swift `String <` applies Unicode NFC normalization, so the decomposed
        // "e\u{0301}" (é) compares as if it were the precomposed U+00E9 — which
        // sorts AFTER "f" (U+0066). UTF-8 byte ordering on the RAW bytes of the
        // decomposed form (0x65 0xCC 0x81) places it BEFORE "f" (0x66). The
        // encoder MUST sort by UTF-8 bytes, not by Swift String comparison.
        let decomposed = "e\u{0301}"
        XCTAssertTrue("f" < decomposed) // Swift String order (NFC-aware)
        XCTAssertTrue(decomposed.utf8.lexicographicallyPrecedes("f".utf8)) // bytes
        let input: JSONValue = .object([
            "f": .integer(2),
            decomposed: .integer(1)
        ])
        let encoded = CanonicalJSON.encode(input)
        // Expected by UTF-8 byte order: decomposed-é (0x65 0xCC 0x81) before "f".
        let expected = Data([
            0x7B, // {
            0x22, 0x65, 0xCC, 0x81, 0x22, 0x3A, 0x31, // "e\u{0301}":1
            0x2C, // ,
            0x22, 0x66, 0x22, 0x3A, 0x32, // "f":2
            0x7D
        ])
        XCTAssertEqual(encoded, expected)
    }

    func testParityVectorsStub() throws {
        guard let url = Bundle.module.url(
            forResource: "test_vectors/canonical_json",
            withExtension: nil
        ) else {
            // Vectors are not yet populated; this test auto-activates later.
            return
        }
        let manager = FileManager.default
        let contents = try manager.contentsOfDirectory(
            at: url,
            includingPropertiesForKeys: nil
        )
        for fileURL in contents where fileURL.pathExtension == "json" {
            _ = try Data(contentsOf: fileURL)
        }
    }

    private func encodeToString(_ value: JSONValue) -> String {
        String(decoding: CanonicalJSON.encode(value), as: UTF8.self)
    }
}
