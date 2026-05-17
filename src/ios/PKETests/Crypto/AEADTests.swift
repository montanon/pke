// Tests for the AES-256-GCM AEAD primitive (HLAM-27).
// Covers wire layout, length-gated rejection, AAD/nonce/tag tamper detection,
// and the shared cross-language fixture bundle when present.

import XCTest
// Import only the swift-crypto symbols we need so the `Crypto.CryptoError`
// typealias does not collide with `PKECrypto.CryptoError` in this file.
import struct Crypto.SymmetricKey
import struct Crypto.SymmetricKeySize
@testable import PKECrypto

final class AEADTests: XCTestCase {

    // MARK: - Round trip

    func test_round_trip_with_random_nonce_real_aad_real_plaintext() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        let aad = Data("pke/v0.1/keywrap/aad".utf8)
        let plaintext = Data("the quick brown fox jumps over the lazy dog".utf8)

        let sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
        let recovered = try AEAD.open(sealed: sealed, key: key, aad: aad)
        XCTAssertEqual(recovered, plaintext)
    }

    // MARK: - Empty plaintext

    func test_empty_plaintext_seals_to_28_bytes_and_opens_to_empty() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        let aad = Data("aad".utf8)

        let sealed = try AEAD.seal(plaintext: Data(), key: key, nonce: nonce, aad: aad)
        XCTAssertEqual(sealed.count, AEAD.nonceByteCount + AEAD.tagByteCount)
        XCTAssertEqual(sealed.count, 28)

        let recovered = try AEAD.open(sealed: sealed, key: key, aad: aad)
        XCTAssertEqual(recovered, Data())
    }

    // MARK: - Empty AAD

    func test_empty_aad_seals_and_opens() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        let plaintext = Data("payload-with-empty-aad".utf8)

        let sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: Data())
        let recovered = try AEAD.open(sealed: sealed, key: key, aad: Data())
        XCTAssertEqual(recovered, plaintext)
    }

    // MARK: - Wire layout

    func test_output_layout_is_nonce_ciphertext_tag() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        let aad = Data("aad".utf8)
        let plaintext = Data(repeating: 0xAB, count: 73)

        let sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: aad)

        XCTAssertEqual(sealed.count, AEAD.nonceByteCount + plaintext.count + AEAD.tagByteCount)
        XCTAssertEqual(Data(sealed.prefix(AEAD.nonceByteCount)), nonce)
        XCTAssertEqual(sealed.suffix(AEAD.tagByteCount).count, AEAD.tagByteCount)
    }

    // MARK: - Wrong key

    func test_open_with_wrong_key_throws_aead() throws {
        let key = SymmetricKey(size: .bits256)
        let wrong = SymmetricKey(size: .bits256)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        let aad = Data("aad".utf8)
        let plaintext = Data("hello".utf8)

        let sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
        XCTAssertThrowsError(try AEAD.open(sealed: sealed, key: wrong, aad: aad)) { error in
            Self.assertAead(error)
        }
    }

    // MARK: - Wrong AAD

    func test_open_with_wrong_aad_throws_aead() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        let plaintext = Data("hello".utf8)

        let sealed = try AEAD.seal(
            plaintext: plaintext,
            key: key,
            nonce: nonce,
            aad: Data("aad-A".utf8)
        )
        XCTAssertThrowsError(
            try AEAD.open(sealed: sealed, key: key, aad: Data("aad-B".utf8))
        ) { error in
            Self.assertAead(error)
        }
    }

    // MARK: - Wrong nonce (byte-flip inside the nonce region)

    func test_open_with_flipped_nonce_byte_throws_aead() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        let aad = Data("aad".utf8)
        let plaintext = Data("hello".utf8)

        var sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
        // Flip a byte inside the nonce region (offset 3).
        let nonceFlipIndex = sealed.startIndex + 3
        sealed[nonceFlipIndex] ^= 0x01

        XCTAssertThrowsError(try AEAD.open(sealed: sealed, key: key, aad: aad)) { error in
            Self.assertAead(error)
        }
    }

    // MARK: - Corrupted tag

    func test_open_with_corrupted_tag_throws_aead() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        let aad = Data("aad".utf8)
        let plaintext = Data("hello".utf8)

        var sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
        let lastIndex = sealed.endIndex - 1
        sealed[lastIndex] ^= 0x01

        XCTAssertThrowsError(try AEAD.open(sealed: sealed, key: key, aad: aad)) { error in
            Self.assertAead(error)
        }
    }

    // MARK: - Short sealed input (length 27, below the 28-byte minimum)

    func test_open_with_short_sealed_input_throws_aead() {
        let key = SymmetricKey(size: .bits256)
        let short = Data(repeating: 0x00, count: 27)
        XCTAssertThrowsError(try AEAD.open(sealed: short, key: key, aad: Data())) { error in
            guard case .aead(let reason) = error as? CryptoError else {
                XCTFail("expected .aead, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("27"), "reason should mention length 27: \(reason)")
        }
    }

    // MARK: - Invalid key length on seal

    func test_seal_with_128_bit_key_throws_aead() {
        let key = SymmetricKey(size: .bits128)
        let nonce = Self.randomBytes(AEAD.nonceByteCount)
        XCTAssertThrowsError(
            try AEAD.seal(plaintext: Data("p".utf8), key: key, nonce: nonce, aad: Data())
        ) { error in
            guard case .aead(let reason) = error as? CryptoError else {
                XCTFail("expected .aead, got \(error)")
                return
            }
            XCTAssertTrue(
                reason.contains("16") && reason.contains("32"),
                "reason should mention bad key length: \(reason)"
            )
        }
    }

    // MARK: - Invalid nonce length on seal

    func test_seal_with_11_byte_nonce_throws_aead() {
        let key = SymmetricKey(size: .bits256)
        let badNonce = Data(repeating: 0x00, count: 11)
        XCTAssertThrowsError(
            try AEAD.seal(plaintext: Data("p".utf8), key: key, nonce: badNonce, aad: Data())
        ) { error in
            guard case .aead(let reason) = error as? CryptoError else {
                XCTFail("expected .aead, got \(error)")
                return
            }
            XCTAssertTrue(
                reason.contains("11") && reason.contains("12"),
                "reason should mention bad nonce length: \(reason)"
            )
        }
    }

    // MARK: - Parametric vector runner

    func test_aes_gcm_vectors_from_bundle() throws {
        let vectors = loadAesGcmVectors()
        if vectors.isEmpty {
            throw XCTSkip("no aes_gcm fixtures present")
        }
        for (_, bundleCase) in vectors.sorted(by: { $0.0.lastPathComponent < $1.0.lastPathComponent }) {
            if bundleCase.valid {
                try runPositiveAesGcmVector(bundleCase)
            } else {
                try runNegativeAesGcmVector(bundleCase)
            }
        }
    }

    private func runPositiveAesGcmVector(_ bundleCase: AesGcmVector) throws {
        let keyBytes = try Self.hexToData(bundleCase.inputs.keyHex)
        let nonce = try Self.hexToData(bundleCase.inputs.nonceHex)
        let aad = try Self.hexToData(bundleCase.inputs.aadHex)
        let plaintext = try Self.hexToData(bundleCase.inputs.plaintextHex)
        let expectedCiphertext = try Self.hexToData(bundleCase.expected.ciphertextHex)
        let expectedTag = try Self.hexToData(bundleCase.expected.tagHex)
        let key = SymmetricKey(data: keyBytes)

        let sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
        XCTAssertEqual(
            sealed.count,
            AEAD.nonceByteCount + expectedCiphertext.count + AEAD.tagByteCount,
            "vector \(bundleCase.name) sealed length"
        )
        let ctSlice = sealed[
            (sealed.startIndex + AEAD.nonceByteCount)..<(sealed.endIndex - AEAD.tagByteCount)
        ]
        XCTAssertEqual(Data(ctSlice), expectedCiphertext, "vector \(bundleCase.name) ciphertext mismatch")
        XCTAssertEqual(
            Data(sealed.suffix(AEAD.tagByteCount)),
            expectedTag,
            "vector \(bundleCase.name) tag mismatch"
        )
        let recovered = try AEAD.open(sealed: sealed, key: key, aad: aad)
        XCTAssertEqual(recovered, plaintext, "vector \(bundleCase.name) round-trip mismatch")
    }

    private func runNegativeAesGcmVector(_ bundleCase: AesGcmVector) throws {
        let keyBytes = try Self.hexToData(bundleCase.inputs.keyHex)
        let nonce = try Self.hexToData(bundleCase.inputs.nonceHex)
        let aad = try Self.hexToData(bundleCase.inputs.aadHex)
        let expectedCiphertext = try Self.hexToData(bundleCase.expected.ciphertextHex)
        let expectedTag = try Self.hexToData(bundleCase.expected.tagHex)
        let key = SymmetricKey(data: keyBytes)

        var sealed = Data(capacity: nonce.count + expectedCiphertext.count + expectedTag.count)
        sealed.append(nonce)
        sealed.append(expectedCiphertext)
        sealed.append(expectedTag)
        XCTAssertThrowsError(
            try AEAD.open(sealed: sealed, key: key, aad: aad),
            "vector \(bundleCase.name) expected to reject"
        ) { error in
            guard case .aead = error as? CryptoError else {
                XCTFail("vector \(bundleCase.name): expected .aead, got \(error)")
                return
            }
        }
    }

    // MARK: - Helpers

    private func loadAesGcmVectors() -> [(URL, AesGcmVector)] {
        var urls: [URL] = []
        if let dir = Bundle.module.url(forResource: "test_vectors/aes_gcm", withExtension: nil),
           let contents = try? FileManager.default.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil
           ) {
            urls.append(contentsOf: contents.filter { $0.pathExtension == "json" })
        }
        if urls.isEmpty,
           let flattened = Bundle.module.urls(
            forResourcesWithExtension: "json",
            subdirectory: "test_vectors/aes_gcm"
           ) {
            urls.append(contentsOf: flattened)
        }
        if urls.isEmpty,
           let flat = Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: nil) {
            urls.append(contentsOf: flat)
        }
        // SwiftPM's `.process` flattens the resource tree, so the canonical
        // subdirectory lookup can come up empty even when the JSONs are
        // present. We schema-filter: a fixture is an AES-GCM vector iff it
        // decodes with the key/nonce/aad/plaintext input shape.
        let decoder = JSONDecoder()
        var matched: [(URL, AesGcmVector)] = []
        for url in urls {
            guard let data = try? Data(contentsOf: url),
                  let vector = try? decoder.decode(AesGcmVector.self, from: data) else {
                continue
            }
            matched.append((url, vector))
        }
        return matched
    }

    private static func assertAead(_ error: Error, file: StaticString = #file, line: UInt = #line) {
        guard case .aead = error as? CryptoError else {
            XCTFail("expected .aead, got \(error)", file: file, line: line)
            return
        }
    }

    private static func randomBytes(_ count: Int) -> Data {
        var out = Data(count: count)
        out.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            for offset in 0..<count {
                base.advanced(by: offset).storeBytes(of: UInt8.random(in: 0...255), as: UInt8.self)
            }
        }
        return out
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

private struct AesGcmVector: Decodable {
    let name: String
    let inputs: Inputs
    let expected: Expected
    let valid: Bool
    let notes: String?

    struct Inputs: Decodable {
        let keyHex: String
        let nonceHex: String
        let aadHex: String
        let plaintextHex: String

        enum CodingKeys: String, CodingKey {
            case keyHex = "key_hex"
            case nonceHex = "nonce_hex"
            case aadHex = "aad_hex"
            case plaintextHex = "plaintext_hex"
        }
    }

    struct Expected: Decodable {
        let ciphertextHex: String
        let tagHex: String

        enum CodingKeys: String, CodingKey {
            case ciphertextHex = "ciphertext_hex"
            case tagHex = "tag_hex"
        }
    }
}
