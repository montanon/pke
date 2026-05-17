// Unit tests for `Base64URL` covering round-trip vectors and every
// documented rejection path (padded input, standard alphabet, non-ASCII,
// invalid length). Reason substrings are asserted to match the Python sibling.

import XCTest
@testable import PKECrypto

final class Base64URLTests: XCTestCase {

    // MARK: Round-trip

    func test_roundtrip_empty_payload() throws {
        try assertRoundTrip(Data())
    }

    func test_roundtrip_one_byte() throws {
        try assertRoundTrip(Data([0x00]))
        try assertRoundTrip(Data([0xFF]))
    }

    func test_roundtrip_two_bytes() throws {
        try assertRoundTrip(Data([0x01, 0x02]))
    }

    func test_roundtrip_three_bytes() throws {
        try assertRoundTrip(Data([0xDE, 0xAD, 0xBE]))
    }

    func test_roundtrip_32_byte_constant_pattern() throws {
        try assertRoundTrip(Data(repeating: 0xAA, count: 32))
    }

    func test_roundtrip_random_ascii_bytes() throws {
        let payload = Data("the quick brown fox jumps over the lazy dog".utf8)
        try assertRoundTrip(payload)
    }

    func test_encode_is_unpadded() {
        // 1-byte input would be `AA==` in standard base64; we must strip padding.
        XCTAssertEqual(PKECrypto.Base64URL.encode(Data([0x00])), "AA")
    }

    // MARK: Negative paths

    func test_decode_rejects_padded_input() {
        assertEncodingThrows(try PKECrypto.Base64URL.decode("AA=="), reasonSubstring: "padded")
    }

    func test_decode_rejects_standard_alphabet() {
        assertEncodingThrows(try PKECrypto.Base64URL.decode("+/"), reasonSubstring: "alphabet")
    }

    func test_decode_rejects_non_ascii_input() {
        // Trailing U+00E9 'é' — non-ASCII is rejected via the alphabet check.
        assertEncodingThrows(try PKECrypto.Base64URL.decode("AA\u{00E9}"), reasonSubstring: "alphabet")
    }

    func test_decode_rejects_length_mod_4_equals_1() {
        assertEncodingThrows(try PKECrypto.Base64URL.decode("A"), reasonSubstring: "mod 4 == 1")
    }

    // MARK: Helpers

    private func assertRoundTrip(
        _ data: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let encoded = PKECrypto.Base64URL.encode(data)
        XCTAssertFalse(encoded.contains("="), "encode emitted padding", file: file, line: line)
        let decoded = try PKECrypto.Base64URL.decode(encoded)
        XCTAssertEqual(decoded, data, file: file, line: line)
    }

    private func assertEncodingThrows(
        _ expression: @autoclosure () throws -> Data,
        reasonSubstring: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            guard case .encoding(let reason) = error as? CryptoError else {
                XCTFail("expected CryptoError.encoding, got \(error)", file: file, line: line)
                return
            }
            XCTAssertTrue(
                reason.contains(reasonSubstring),
                "reason '\(reason)' missing substring '\(reasonSubstring)'",
                file: file,
                line: line
            )
        }
    }
}
