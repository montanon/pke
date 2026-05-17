import Foundation
import XCTest
@testable import PKEUI

final class FingerprintTests: XCTestCase {

    func test_display_truncatesToFirst8AndLast8WithEllipsis() {
        // SHA-256 of 65 zero bytes is a fixed vector. The expected value was
        // pre-computed via `python3 -c "import hashlib; print(hashlib.sha256(b'\\x00'*65).hexdigest())"`
        // so the assertion verifies the entire pipeline (hash + hex + slice)
        // against an external oracle.
        let raw = Data(repeating: 0x00, count: 65)
        let expected = "98ce42de\u{22EF}108f75f7"

        XCTAssertEqual(Fingerprint.display(rawPublicKey: raw), expected)
    }

    func test_display_returnsEmDashOnEmptyInput() {
        XCTAssertEqual(Fingerprint.display(rawPublicKey: Data()), "—")
    }

    func test_display_isStableAcrossCalls() {
        let raw = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let first = Fingerprint.display(rawPublicKey: raw)
        let second = Fingerprint.display(rawPublicKey: raw)

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.count, 17, "8 head + middle ellipsis (1 char) + 8 tail")
    }

    func test_fullHex_isLowercaseHexOfRawBytes() {
        let raw = Data([0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(Fingerprint.fullHex(rawPublicKey: raw), "deadbeef")
    }

    func test_fullHex_returnsEmptyOnEmptyInput() {
        XCTAssertEqual(Fingerprint.fullHex(rawPublicKey: Data()), "")
    }

    func test_fullHex_padsSingleHexDigit() {
        let raw = Data([0x00, 0x0F, 0xF0, 0xFF])
        XCTAssertEqual(Fingerprint.fullHex(rawPublicKey: raw), "000ff0ff")
    }
}
