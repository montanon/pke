// Tests for the HKDF-SHA256 derivation primitive (HLAM-27).
// Covers round-trip determinism, length-bounds rejection, empty-salt/info,
// the RFC 5869 Test Case 1 vector, and the shared cross-language fixtures.

import XCTest
// Import only the swift-crypto symbol we need so the `Crypto.CryptoError`
// typealias does not collide with `PKECrypto.CryptoError` in this file.
import struct Crypto.SymmetricKey
@testable import PKECrypto

final class KDFTests: XCTestCase {

    // MARK: - Determinism + length

    func test_hkdfSHA256_is_deterministic_and_matches_requested_length() throws {
        let secret = Data("ikm bytes".utf8)
        let salt = Data("salt".utf8)
        let info = Data("info".utf8)
        let length = 48
        let first = try KDF.hkdfSHA256(secret: secret, salt: salt, info: info, length: length)
        let second = try KDF.hkdfSHA256(secret: secret, salt: salt, info: info, length: length)
        let firstBytes = first.withUnsafeBytes { Data($0) }
        let secondBytes = second.withUnsafeBytes { Data($0) }
        XCTAssertEqual(firstBytes, secondBytes)
        XCTAssertEqual(firstBytes.count, length)
    }

    // MARK: - Length bounds (RFC 5869 cap)

    func test_hkdfSHA256_rejects_zero_length_as_encoding() {
        XCTAssertThrowsError(
            try KDF.hkdfSHA256(secret: Data("x".utf8), salt: Data(), info: Data(), length: 0)
        ) { error in
            guard case .encoding(let reason) = error as? CryptoError else {
                XCTFail("expected encoding, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("0"), "reason should mention length 0, got: \(reason)")
        }
    }

    func test_hkdfSHA256_rejects_above_max_as_encoding() {
        let overCap = KDF.maxOutputByteCount + 1
        XCTAssertThrowsError(
            try KDF.hkdfSHA256(secret: Data("x".utf8), salt: Data(), info: Data(), length: overCap)
        ) { error in
            guard case .encoding(let reason) = error as? CryptoError else {
                XCTFail("expected encoding, got \(error)")
                return
            }
            XCTAssertTrue(
                reason.contains("\(overCap)"),
                "reason should mention requested length, got: \(reason)"
            )
        }
    }

    // MARK: - Empty salt / empty info both succeed

    func test_hkdfSHA256_empty_salt_succeeds() throws {
        let key = try KDF.hkdfSHA256(
            secret: Data("ikm".utf8),
            salt: Data(),
            info: Data("info".utf8),
            length: 32
        )
        XCTAssertEqual(key.withUnsafeBytes { Data($0) }.count, 32)
    }

    func test_hkdfSHA256_empty_info_succeeds() throws {
        let key = try KDF.hkdfSHA256(
            secret: Data("ikm".utf8),
            salt: Data("salt".utf8),
            info: Data(),
            length: 32
        )
        XCTAssertEqual(key.withUnsafeBytes { Data($0) }.count, 32)
    }

    // MARK: - RFC 5869 Test Case 1

    func test_hkdfSHA256_rfc5869_test_case_1() throws {
        let ikm = Data(repeating: 0x0b, count: 22)
        let salt = try Self.hexToData("000102030405060708090a0b0c")
        let info = try Self.hexToData("f0f1f2f3f4f5f6f7f8f9")
        let expected = try Self.hexToData(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" // pragma: allowlist secret
        )
        let key = try KDF.hkdfSHA256(secret: ikm, salt: salt, info: info, length: 42)
        let bytes = key.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytes, expected)
    }

    // MARK: - Parametric runner against shared fixtures

    func test_hkdf_sha256_vectors_from_bundle() throws {
        let vectors = loadHkdfVectors()
        if vectors.isEmpty {
            throw XCTSkip("no hkdf_sha256 fixtures present")
        }
        for (url, vector) in vectors.sorted(by: { $0.0.lastPathComponent < $1.0.lastPathComponent }) {
            _ = url
            let ikm = try Self.hexToData(vector.inputs.ikmHex)
            let salt = try Self.hexToData(vector.expected.saltHex)
            let info = try Self.hexToData(vector.expected.infoHex)
            let okm = try Self.hexToData(vector.expected.okmHex)

            let key = try KDF.hkdfSHA256(
                secret: ikm,
                salt: salt,
                info: info,
                length: okm.count
            )
            let derived = key.withUnsafeBytes { Data($0) }

            if vector.valid {
                XCTAssertEqual(
                    derived,
                    okm,
                    "hkdf_sha256 vector \(vector.name) expected to match"
                )
            } else {
                XCTAssertNotEqual(
                    derived,
                    okm,
                    "hkdf_sha256 vector \(vector.name) expected to diverge"
                )
            }
        }
    }

    // MARK: - Helpers

    private func loadHkdfVectors() -> [(URL, HkdfVector)] {
        var urls: [URL] = []
        if let dir = Bundle.module.url(forResource: "test_vectors/hkdf_sha256", withExtension: nil),
           let contents = try? FileManager.default.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil
           ) {
            urls.append(contentsOf: contents.filter { $0.pathExtension == "json" })
        }
        if urls.isEmpty,
           let flattened = Bundle.module.urls(
            forResourcesWithExtension: "json",
            subdirectory: "test_vectors/hkdf_sha256"
           ) {
            urls.append(contentsOf: flattened)
        }
        if urls.isEmpty,
           let flat = Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: nil) {
            urls.append(contentsOf: flat)
        }
        // SwiftPM's `.process` flattens the resource tree, so the canonical
        // subdirectory lookup can come up empty even when the JSONs are
        // present. We schema-filter: a fixture is an HKDF vector iff it
        // decodes with `ikm_hex` in inputs and salt/info/okm in expected.
        let decoder = JSONDecoder()
        var matched: [(URL, HkdfVector)] = []
        for url in urls {
            guard let data = try? Data(contentsOf: url),
                  let vector = try? decoder.decode(HkdfVector.self, from: data) else {
                continue
            }
            matched.append((url, vector))
        }
        return matched
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

private struct HkdfVector: Decodable {
    let name: String
    let inputs: Inputs
    let expected: Expected
    let valid: Bool
    let notes: String?

    struct Inputs: Decodable {
        let ikmHex: String

        enum CodingKeys: String, CodingKey {
            case ikmHex = "ikm_hex"
        }
    }

    struct Expected: Decodable {
        let saltHex: String
        let infoHex: String
        let okmHex: String

        enum CodingKeys: String, CodingKey {
            case saltHex = "salt_hex"
            case infoHex = "info_hex"
            case okmHex = "okm_hex"
        }
    }
}
