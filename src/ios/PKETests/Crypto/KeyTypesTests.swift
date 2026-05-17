// Tests for `SigningPublicKey` / `AgreementPublicKey` base64url round-trip and
// the documented `.encoding` rejection branches (HLAM-28 AC #6).

import XCTest
import enum Crypto.P256
@testable import PKECrypto

final class KeyTypesTests: XCTestCase {

    // MARK: - AC #6 — round trip

    func test_signing_public_key_round_trips_through_base64url() throws {
        let key = P256.Signing.PrivateKey().publicKey
        let wrapper = SigningPublicKey(key)
        let recovered = try SigningPublicKey(base64url: wrapper.base64url)
        XCTAssertEqual(
            wrapper.underlying.x963Representation,
            recovered.underlying.x963Representation
        )
        XCTAssertEqual(wrapper, recovered)
    }

    func test_agreement_public_key_round_trips_through_base64url() throws {
        let key = P256.KeyAgreement.PrivateKey().publicKey
        let wrapper = AgreementPublicKey(key)
        let recovered = try AgreementPublicKey(base64url: wrapper.base64url)
        XCTAssertEqual(
            wrapper.underlying.x963Representation,
            recovered.underlying.x963Representation
        )
        XCTAssertEqual(wrapper, recovered)
    }

    // MARK: - Equatable

    func test_signing_public_key_equatable_compares_underlying_bytes() {
        let key1 = P256.Signing.PrivateKey().publicKey
        let key2 = P256.Signing.PrivateKey().publicKey
        XCTAssertEqual(SigningPublicKey(key1), SigningPublicKey(key1))
        XCTAssertNotEqual(SigningPublicKey(key1), SigningPublicKey(key2))
    }

    func test_agreement_public_key_equatable_compares_underlying_bytes() {
        let key1 = P256.KeyAgreement.PrivateKey().publicKey
        let key2 = P256.KeyAgreement.PrivateKey().publicKey
        XCTAssertEqual(AgreementPublicKey(key1), AgreementPublicKey(key1))
        XCTAssertNotEqual(AgreementPublicKey(key1), AgreementPublicKey(key2))
    }

    // MARK: - base64url rejection branches

    func test_signing_public_key_rejects_padded_base64() {
        let raw = P256.Signing.PrivateKey().publicKey.x963Representation
        let padded = raw.base64EncodedString()  // standard base64 with `=` padding
        XCTAssertThrowsError(try SigningPublicKey(base64url: padded)) { error in
            assertEncoding(error, contains: "padding")
        }
    }

    func test_signing_public_key_rejects_standard_base64_chars() {
        // Construct an input that, once base64-encoded, contains '+' or '/'.
        // Bytes 0xfb 0xff produce "+/", which is guaranteed not base64url.
        let needsStandard = Data([0xfb, 0xff, 0xff, 0xff, 0xff, 0xff])
        var encoded = needsStandard.base64EncodedString()
        while encoded.hasSuffix("=") {
            encoded.removeLast()
        }
        XCTAssertTrue(encoded.contains("+") || encoded.contains("/"))
        XCTAssertThrowsError(try SigningPublicKey(base64url: encoded)) { error in
            assertEncoding(error, contains: "'+'")
        }
    }

    func test_signing_public_key_rejects_wrong_length() {
        // 64 bytes (not the required 65).
        let bogus = Data(repeating: 0x04, count: 64)
        let encoded = KeyTypeCoding.encodeBase64URLNoPad(bogus)
        XCTAssertThrowsError(try SigningPublicKey(base64url: encoded)) { error in
            assertEncoding(error, contains: "x963 rejected")
        }
    }

    func test_signing_public_key_rejects_compressed_point() {
        // 33-byte compressed `0x02 ‖ X` — swift-crypto's x963 init rejects.
        let compressed = Data([0x02]) + Data(repeating: 0x00, count: 32)
        let encoded = KeyTypeCoding.encodeBase64URLNoPad(compressed)
        XCTAssertThrowsError(try SigningPublicKey(base64url: encoded)) { error in
            assertEncoding(error, contains: "x963 rejected")
        }
    }

    func test_signing_public_key_rejects_non_alphabet_chars() {
        // Whitespace, newline, and unicode are out of RFC 4648 §5 alphabet.
        for needle in ["AA AA", "AA\nBB", "abc\u{00E9}"] {
            XCTAssertThrowsError(try SigningPublicKey(base64url: needle)) { error in
                assertEncoding(error, contains: "non-alphabet")
            }
        }
    }

    func test_signing_public_key_rejects_off_curve_point() {
        // 65-byte 0x04 prefix with random coordinates — almost certainly off curve.
        let offCurve = Data([0x04]) + Data(repeating: 0x01, count: 64)
        let encoded = KeyTypeCoding.encodeBase64URLNoPad(offCurve)
        XCTAssertThrowsError(try SigningPublicKey(base64url: encoded)) { error in
            assertEncoding(error, contains: "x963 rejected")
        }
    }

    // Mirror the rejection matrix for AgreementPublicKey.

    func test_agreement_public_key_rejects_padded_base64() {
        let raw = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let padded = raw.base64EncodedString()
        XCTAssertThrowsError(try AgreementPublicKey(base64url: padded)) { error in
            assertEncoding(error, contains: "padding")
        }
    }

    func test_agreement_public_key_rejects_wrong_length() {
        let bogus = Data(repeating: 0x04, count: 64)
        let encoded = KeyTypeCoding.encodeBase64URLNoPad(bogus)
        XCTAssertThrowsError(try AgreementPublicKey(base64url: encoded)) { error in
            assertEncoding(error, contains: "x963 rejected")
        }
    }

    func test_agreement_public_key_rejects_compressed_point() {
        let compressed = Data([0x03]) + Data(repeating: 0x00, count: 32)
        let encoded = KeyTypeCoding.encodeBase64URLNoPad(compressed)
        XCTAssertThrowsError(try AgreementPublicKey(base64url: encoded)) { error in
            assertEncoding(error, contains: "x963 rejected")
        }
    }

    // MARK: - Helpers

    private func assertEncoding(
        _ error: Error,
        contains needle: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .encoding(let reason) = error as? CryptoError else {
            XCTFail("expected CryptoError.encoding, got \(error)", file: file, line: line)
            return
        }
        XCTAssertTrue(
            reason.contains(needle),
            "reason \"\(reason)\" should contain \"\(needle)\"",
            file: file,
            line: line
        )
    }
}
