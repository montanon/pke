// Surface tests for `DecryptionError` (HLAM-118): Equatable conformance
// and `CustomStringConvertible` description format. Reason strings are
// kept stable for callers that pattern-match.

import XCTest
@testable import PKERecipient

final class DecryptionErrorTests: XCTestCase {

    func test_equatable_distinguishesCasesAndReasons() {
        XCTAssertEqual(
            DecryptionError.unwrapFailed(reason: "x"),
            DecryptionError.unwrapFailed(reason: "x")
        )
        XCTAssertNotEqual(
            DecryptionError.unwrapFailed(reason: "x"),
            DecryptionError.unwrapFailed(reason: "y")
        )
        XCTAssertNotEqual(
            DecryptionError.unwrapFailed(reason: "x"),
            DecryptionError.decryptFailed(reason: "x")
        )
        XCTAssertEqual(
            DecryptionError.malformedCiphertext(byteCount: 12),
            DecryptionError.malformedCiphertext(byteCount: 12)
        )
        XCTAssertEqual(
            DecryptionError.unsupportedAlgorithm("v0"),
            DecryptionError.unsupportedAlgorithm("v0")
        )
    }

    func test_description_includesCaseLabelAndPayload() {
        XCTAssertEqual(
            DecryptionError.unwrapFailed(reason: "recipient mismatch").description,
            "unwrapFailed: recipient mismatch"
        )
        XCTAssertEqual(
            DecryptionError.decryptFailed(reason: "open failed").description,
            "decryptFailed: open failed"
        )
        XCTAssertEqual(
            DecryptionError.malformedCiphertext(byteCount: 4).description,
            "malformedCiphertext: byteCount 4"
        )
        XCTAssertEqual(
            DecryptionError.unsupportedAlgorithm("future-alg").description,
            "unsupportedAlgorithm: future-alg"
        )
    }
}
