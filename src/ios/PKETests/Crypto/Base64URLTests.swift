import XCTest
@testable import PKECrypto

final class Base64URLTests: XCTestCase {
    func testEmptyRoundTrip() throws {
        XCTAssertEqual(Base64URL.encode(Data()), "")
        XCTAssertEqual(try Base64URL.decode(""), Data())
    }

    func testKnownVectorExercisesDashUnderscore() throws {
        let bytes = Data([0xFB, 0xFF, 0xFE])
        let encoded = Base64URL.encode(bytes)
        XCTAssertEqual(encoded, "-__-")
        XCTAssertEqual(try Base64URL.decode(encoded), bytes)
    }

    func testDeterministic256ByteRoundTrip() throws {
        let bytes = Data((0..<256).map { UInt8($0) })
        let encoded = Base64URL.encode(bytes)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertEqual(try Base64URL.decode(encoded), bytes)
    }

    func testPaddedInputRejected() {
        XCTAssertThrowsError(try Base64URL.decode("AAAA=")) { error in
            guard let typed = error as? CryptoError else {
                XCTFail("expected CryptoError, got \(error)")
                return
            }
            if case .encoding = typed { } else {
                XCTFail("expected .encoding, got \(typed)")
            }
        }
    }

    func testStandardAlphabetInputRejected() {
        XCTAssertThrowsError(try Base64URL.decode("a+b/")) { error in
            guard let typed = error as? CryptoError else {
                XCTFail("expected CryptoError, got \(error)")
                return
            }
            if case .encoding = typed { } else {
                XCTFail("expected .encoding, got \(typed)")
            }
        }
    }

    func testNonAlphabetCharacterRejected() {
        XCTAssertThrowsError(try Base64URL.decode("a!b")) { error in
            guard let typed = error as? CryptoError else {
                XCTFail("expected CryptoError, got \(error)")
                return
            }
            if case .encoding = typed { } else {
                XCTFail("expected .encoding, got \(typed)")
            }
        }
    }

    func testStandardAlphabetUppercaseStillRejected() {
        XCTAssertThrowsError(try Base64URL.decode("ABCD+/")) { error in
            guard let typed = error as? CryptoError else {
                XCTFail("expected CryptoError, got \(error)")
                return
            }
            if case .encoding = typed { } else {
                XCTFail("expected .encoding, got \(typed)")
            }
        }
    }
}
