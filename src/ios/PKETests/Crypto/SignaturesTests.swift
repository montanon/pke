// Tests for the ECDSA P-256 / raw-P1363 signing primitive (HLAM-25).
// Covers length-gated rejection, parse-vs-verify error taxonomy, and the
// shared cross-language fixture bundle when present.

import XCTest
// Import only the swift-crypto symbols we need so the `Crypto.CryptoError`
// typealias does not collide with `PKECrypto.CryptoError` in this file.
import enum Crypto.P256
@testable import PKECrypto

final class SignaturesTests: XCTestCase {

    // MARK: - AC #5 — sign produces exactly 64 bytes raw P1363

    func test_sign_returns_64_byte_raw_p1363() throws {
        let key = P256.Signing.PrivateKey()
        let payload = Data("hello pke".utf8)
        let signature = try Signatures.sign(payload: payload, with: key)
        XCTAssertEqual(signature.count, 64)
    }

    // MARK: - AC #6 — round trip

    func test_sign_and_verify_round_trip() throws {
        let key = P256.Signing.PrivateKey()
        let payload = Data("round trip payload".utf8)
        let signature = try Signatures.sign(payload: payload, with: key)
        XCTAssertNoThrow(
            try Signatures.verify(signature, of: payload, by: key.publicKey)
        )
    }

    // MARK: - AC #7 — parseable 64-byte signature that fails math

    func test_verify_rejects_64_byte_garbage_as_signatureVerification() throws {
        // Sign payload A with K1, then verify under K2 — guaranteed valid raw
        // P1363 (parses cleanly) but guaranteed to fail the math.
        let key1 = P256.Signing.PrivateKey()
        let key2 = P256.Signing.PrivateKey()
        let payload = Data("cross-key payload".utf8)
        let signature = try Signatures.sign(payload: payload, with: key1)
        XCTAssertEqual(signature.count, 64)
        XCTAssertThrowsError(
            try Signatures.verify(signature, of: payload, by: key2.publicKey)
        ) { error in
            guard case .signatureVerification = error as? CryptoError else {
                XCTFail("expected signatureVerification, got \(error)")
                return
            }
        }
    }

    // MARK: - AC #8 part one — non-64 inputs rejected as signatureFormat

    func test_verify_rejects_non_64_byte_as_signatureFormat() {
        let key = P256.Signing.PrivateKey()
        let payload = Data("len-check".utf8)
        for length in [63, 65] {
            let bogus = Data(repeating: 0x01, count: length)
            XCTAssertThrowsError(
                try Signatures.verify(bogus, of: payload, by: key.publicKey)
            ) { error in
                guard case .signatureFormat(let reason) = error as? CryptoError else {
                    XCTFail("expected signatureFormat for length \(length), got \(error)")
                    return
                }
                XCTAssertTrue(
                    reason.contains("\(length)"),
                    "reason should mention length, got: \(reason)"
                )
            }
        }
    }

    // MARK: - AC #8 part two — DER-shaped input rejected by length gate

    func test_verify_rejects_DER_leading_byte_as_signatureFormat() {
        let key = P256.Signing.PrivateKey()
        let payload = Data("der-check".utf8)
        // Typical DER ECDSA signature is ~70-72 bytes, starts with 0x30 (SEQUENCE).
        var der = Data([0x30, 0x46])
        der.append(Data(repeating: 0x00, count: 70))
        XCTAssertEqual(der.count, 72)
        XCTAssertThrowsError(
            try Signatures.verify(der, of: payload, by: key.publicKey)
        ) { error in
            guard case .signatureFormat = error as? CryptoError else {
                XCTFail("expected signatureFormat for DER-shaped input, got \(error)")
                return
            }
        }
    }

    // MARK: - Zero-length input

    func test_verify_rejects_zero_length_signature_as_signatureFormat() {
        let key = P256.Signing.PrivateKey()
        let payload = Data("z".utf8)
        XCTAssertThrowsError(
            try Signatures.verify(Data(), of: payload, by: key.publicKey)
        ) { error in
            guard case .signatureFormat(let reason) = error as? CryptoError else {
                XCTFail("expected signatureFormat, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("0"), "reason should mention length 0, got: \(reason)")
        }
    }

    // MARK: - Empty payload edge case

    func test_empty_payload_signs_and_verifies() throws {
        let key = P256.Signing.PrivateKey()
        let signature = try Signatures.sign(payload: Data(), with: key)
        XCTAssertEqual(signature.count, 64)
        XCTAssertNoThrow(
            try Signatures.verify(signature, of: Data(), by: key.publicKey)
        )
    }

    // MARK: - AC #9 — parametric vector runner against shared fixtures

    func test_ecdsa_p256_vectors_from_bundle() throws {
        // Schema (see src/shared/test_vectors/ecdsa_p256/*.json):
        //   inputs.public_key_uncompressed_hex (65-byte 0x04‖X‖Y, hex)
        //   inputs.message_hex                 (arbitrary bytes, hex)
        //   expected.signature_p1363_hex       (64 bytes, hex)
        //
        // Positive vectors verify successfully; negatives mutate the
        // expected signature and must fail verification with
        // `CryptoError.signatureVerification`.
        let vectors = loadEcdsaVectors()
        if vectors.isEmpty {
            throw XCTSkip("no ecdsa_p256 fixtures present")
        }

        for (_, bundleCase) in vectors {
            let pubBytes = try Self.hexToData(bundleCase.inputs.publicKeyUncompressedHex)
            let pub = try P256.Signing.PublicKey(x963Representation: pubBytes)
            let message = try Self.hexToData(bundleCase.inputs.messageHex)
            let signature = try Self.hexToData(bundleCase.expected.signatureP1363Hex)

            if bundleCase.valid {
                XCTAssertNoThrow(
                    try Signatures.verify(signature, of: message, by: pub),
                    "vector \(bundleCase.name) expected to verify"
                )
            } else {
                XCTAssertThrowsError(
                    try Signatures.verify(signature, of: message, by: pub),
                    "vector \(bundleCase.name) expected to reject"
                ) { error in
                    self.assertMatches(expected: bundleCase.expected.error,
                                       error: error,
                                       name: bundleCase.name)
                }
            }
        }
    }

    // MARK: - Helpers

    private func loadEcdsaVectors() -> [(URL, EcdsaVector)] {
        var urls: [URL] = []
        if let dir = Bundle.module.url(forResource: "test_vectors/ecdsa_p256", withExtension: nil),
           let contents = try? FileManager.default.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil
           ) {
            urls.append(contentsOf: contents.filter { $0.pathExtension == "json" })
        }
        if urls.isEmpty,
           let flattened = Bundle.module.urls(
            forResourcesWithExtension: "json",
            subdirectory: "test_vectors/ecdsa_p256"
           ) {
            urls.append(contentsOf: flattened)
        }
        // SwiftPM's `.process` flattens the resource tree; fall back to a
        // flat search and let schema-decoding gate inclusion to
        // ecdsa_p256-shaped fixtures only.
        if urls.isEmpty,
           let flat = Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: nil) {
            urls.append(contentsOf: flat)
        }
        let decoder = JSONDecoder()
        var matched: [(URL, EcdsaVector)] = []
        for url in urls.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard let data = try? Data(contentsOf: url),
                  let vector = try? decoder.decode(EcdsaVector.self, from: data) else {
                continue
            }
            matched.append((url, vector))
        }
        return matched
    }

    private func assertMatches(expected: String?, error: Error, name: String) {
        switch error as? CryptoError {
        case .signatureFormat(let reason):
            if let expected, expected != "signatureFormat" {
                XCTFail("vector \(name): got signatureFormat (\(reason)), expected \(expected)")
            }
        case .signatureVerification:
            if let expected, expected != "signatureVerification" {
                XCTFail("vector \(name): got signatureVerification, expected \(expected)")
            }
        default:
            XCTFail("vector \(name): unexpected error \(error)")
        }
    }

    private static func hexToData(_ hex: String) throws -> Data {
        guard hex.count.isMultiple(of: 2) else {
            throw HexError.oddLength
        }
        var out = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw HexError.invalidCharacter
            }
            out.append(byte)
            index = next
        }
        return out
    }

    private enum HexError: Error {
        case oddLength
        case invalidCharacter
    }
}

// MARK: - Fixture decoding

private struct EcdsaVector: Decodable {
    let name: String
    let inputs: Inputs
    let expected: Expected
    let valid: Bool
    let notes: String?

    struct Inputs: Decodable {
        let publicKeyUncompressedHex: String
        let messageHex: String

        enum CodingKeys: String, CodingKey {
            case publicKeyUncompressedHex = "public_key_uncompressed_hex"
            case messageHex = "message_hex"
        }
    }

    struct Expected: Decodable {
        let signatureP1363Hex: String
        // Optional in the fixture format: positive vectors omit it,
        // negative vectors may carry a discriminator like "signatureVerification".
        let error: String?

        enum CodingKeys: String, CodingKey {
            case signatureP1363Hex = "signature_p1363_hex"
            case error
        }
    }
}
