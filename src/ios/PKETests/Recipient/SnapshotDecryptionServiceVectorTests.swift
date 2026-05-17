// Vector-driven tests for `SnapshotDecryptionService` (HLAM-118, AC #7).
//
// Iterates over the shared `src/shared/test_vectors/{ecdh_wrap,aes_gcm}/`
// corpus and asserts byte-identical results against the canonical
// fixtures. Source-tree resolution uses `#filePath` per the pattern
// already established in `KeyWrapTests.test_ecdh_wrap_vectors_from_bundle`
// — the `.process` resource declaration in `Package.swift` is kept for
// discoverability and tooling but not relied on at runtime (`.process`
// flattens basenames, which breaks `Bundle.module` subdirectory lookups).

import XCTest
import struct Crypto.SymmetricKey
import enum Crypto.P256
@testable import PKECrypto
@testable import PKEProtocol
@testable import PKERecipient

final class SnapshotDecryptionServiceVectorTests: XCTestCase {

    // MARK: - AC #7 — ecdh_wrap byte-identity

    func test_unwrap_vectors_from_bundle() throws {
        let urls = loadVectorURLs(subdirectory: "ecdh_wrap")
        if urls.isEmpty {
            throw XCTSkip("no ecdh_wrap fixtures present")
        }
        XCTAssertGreaterThanOrEqual(urls.count, 3, "expected p1, p2, n1 fixtures")

        for url in urls.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            let data = try Data(contentsOf: url)
            let vector = try JSONDecoder().decode(EcdhVector.self, from: data)
            try runEcdhVector(vector)
        }
    }

    // MARK: - AC #4 / #5 — aes_gcm byte-identity

    func test_decrypt_vectors_from_bundle() throws {
        let urls = loadVectorURLs(subdirectory: "aes_gcm")
        if urls.isEmpty {
            throw XCTSkip("no aes_gcm fixtures present")
        }
        XCTAssertGreaterThanOrEqual(urls.count, 2, "expected at least one positive + one negative")

        for url in urls.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            let data = try Data(contentsOf: url)
            let vector = try JSONDecoder().decode(AesGcmVector.self, from: data)
            try runAesGcmVector(vector)
        }
    }

    // MARK: - Per-vector runners

    private func runEcdhVector(_ vector: EcdhVector) throws {
        let recipientPriv = try P256.KeyAgreement.PrivateKey(
            pemRepresentation: vector.inputs.recipientPrivateKeyPkcs8Pem
        )
        let senderPriv = try P256.KeyAgreement.PrivateKey(
            pemRepresentation: vector.inputs.senderPrivateKeyPkcs8Pem
        )
        let wrapped = try Self.hexToData(vector.expected.wrappedKeyHex)
        let recipientPubRaw = try Self.hexToData(vector.inputs.recipientPublicKeyUncompressedHex)
        let expectedSnapshotKey = try Self.hexToData(vector.inputs.snapshotKeyHex)

        let grant = KeyGrant(
            version: "0.1",
            grantId: "grant-\(vector.name)",
            snapshotId: vector.inputs.snapshotId,
            recipientEncryptionPublicKey: recipientPubRaw,
            wrappedSnapshotKey: wrapped,
            wrappingAlgorithm: "ecdhp256+aesgcm256",
            grantedBySigningPublicKey: Data(repeating: 0x04, count: 65),
            grantTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 1_700_000_000)),
            grantSignature: Data(repeating: 0xFE, count: 64)
        )

        let service = SnapshotDecryptionService(unwrap: { grant, ownerPub in
            try KeyWrap.unwrap(
                grant.wrappedSnapshotKey,
                recipientPrivate: recipientPriv,
                ownerPublic: ownerPub,
                snapshotId: grant.snapshotId
            )
        })
        let ownerPub = AgreementPublicKey(senderPriv.publicKey)

        if vector.valid {
            let recovered = try service.unwrap(
                grant: grant,
                ownerAgreementPublicKey: ownerPub
            )
            let recoveredBytes: Data = recovered.withUnsafeBytes { buffer in
                Data(buffer)
            }
            XCTAssertEqual(
                recoveredBytes,
                expectedSnapshotKey,
                "vector \(vector.name): snapshot key mismatch"
            )
        } else {
            XCTAssertThrowsError(
                try service.unwrap(grant: grant, ownerAgreementPublicKey: ownerPub),
                "vector \(vector.name): expected unwrap to throw"
            ) { error in
                guard case DecryptionError.unwrapFailed = error else {
                    XCTFail("vector \(vector.name): expected unwrapFailed, got \(error)")
                    return
                }
            }
        }
    }

    private func runAesGcmVector(_ vector: AesGcmVector) throws {
        let keyBytes = try Self.hexToData(vector.inputs.keyHex)
        let nonce = try Self.hexToData(vector.inputs.nonceHex)
        let aad = try Self.hexToData(vector.inputs.aadHex)
        let plaintext = try Self.hexToData(vector.inputs.plaintextHex)
        let expectedCiphertext = try Self.hexToData(vector.expected.ciphertextHex)
        let expectedTag = try Self.hexToData(vector.expected.tagHex)

        var sealed = Data()
        sealed.append(nonce)
        sealed.append(expectedCiphertext)
        sealed.append(expectedTag)

        let service = SnapshotDecryptionService(unwrap: { _, _ in
            throw DecryptionError.unwrapFailed(reason: "unused in aes_gcm vector path")
        })
        let snapshotKey = SymmetricKey(data: keyBytes)

        if vector.valid {
            let recovered = try service.decrypt(
                snapshotKey: snapshotKey,
                ciphertext: sealed,
                aad: aad
            )
            XCTAssertEqual(
                recovered,
                plaintext,
                "vector \(vector.name): plaintext mismatch"
            )
        } else {
            XCTAssertThrowsError(
                try service.decrypt(snapshotKey: snapshotKey, ciphertext: sealed, aad: aad),
                "vector \(vector.name): expected decrypt to throw"
            ) { error in
                guard case DecryptionError.decryptFailed = error else {
                    XCTFail("vector \(vector.name): expected decryptFailed, got \(error)")
                    return
                }
            }
        }
    }

    // MARK: - Fixture loading

    private func loadVectorURLs(
        subdirectory: String,
        file: StaticString = #filePath
    ) -> [URL] {
        // From this file: src/ios/PKETests/Recipient/SnapshotDecryptionServiceVectorTests.swift
        // up four levels lands at the repo root.
        let dir = URL(fileURLWithPath: "\(file)")
            .deletingLastPathComponent()   // PKETests/Recipient
            .deletingLastPathComponent()   // PKETests
            .deletingLastPathComponent()   // ios
            .deletingLastPathComponent()   // src
            .appendingPathComponent("shared/test_vectors", isDirectory: true)
            .appendingPathComponent(subdirectory, isDirectory: true)
        guard let contents = try? FileManager.default.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil
        ) else {
            return []
        }
        return contents.filter { $0.pathExtension == "json" }
    }

    private static func hexToData(_ hex: String) throws -> Data {
        guard hex.count.isMultiple(of: 2) else { throw HexError.oddLength }
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

// MARK: - Fixture schemas

private struct EcdhVector: Decodable {
    let name: String
    let inputs: Inputs
    let expected: Expected
    let valid: Bool

    struct Inputs: Decodable {
        let snapshotId: String
        let snapshotKeyHex: String
        let senderPrivateKeyPkcs8Pem: String
        let recipientPrivateKeyPkcs8Pem: String
        let recipientPublicKeyUncompressedHex: String

        enum CodingKeys: String, CodingKey {
            case snapshotId = "snapshot_id"
            case snapshotKeyHex = "snapshot_key_hex"
            case senderPrivateKeyPkcs8Pem = "sender_private_key_pkcs8_pem"   // pragma: allowlist secret
            case recipientPrivateKeyPkcs8Pem = "recipient_private_key_pkcs8_pem"   // pragma: allowlist secret
            case recipientPublicKeyUncompressedHex = "recipient_public_key_uncompressed_hex"
        }
    }

    struct Expected: Decodable {
        let wrappedKeyHex: String

        enum CodingKeys: String, CodingKey {
            case wrappedKeyHex = "wrapped_key_hex"
        }
    }
}

private struct AesGcmVector: Decodable {
    let name: String
    let inputs: Inputs
    let expected: Expected
    let valid: Bool

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
