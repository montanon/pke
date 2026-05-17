// Vector-runner support for `KeyWrapTests.test_ecdh_wrap_vectors_from_bundle`.
// Holds the JSON schema for `src/shared/test_vectors/ecdh_wrap/*.json`, the
// materials struct, and the per-vector assertion helpers. Lifted out of
// `KeyWrapTests.swift` so the test class stays under the SwiftLint
// `type_body_length` and `file_length` thresholds.

import XCTest
import enum Crypto.AES
import enum Crypto.P256
import struct Crypto.SymmetricKey
@testable import PKECrypto

extension KeyWrapTests {

    struct VectorMaterials {
        let snapshotId: String
        let snapshotKey: SymmetricKey
        let snapshotKeyBytes: Data
        let senderPriv: P256.KeyAgreement.PrivateKey
        let recipientPriv: P256.KeyAgreement.PrivateKey
        let recipientPubRaw: Data
        let nonce: AES.GCM.Nonce
        let sharedSecret: Data
    }

    func runVector(_ vector: EcdhWrapVector) throws {
        let materials = try resolveMaterials(vector)
        assertIntermediates(vector: vector, materials: materials)
        let expectedWrapped = try hexToData(vector.expected.wrappedKeyHex)
        if vector.valid {
            try assertPositiveVector(
                vector: vector,
                materials: materials,
                expectedWrapped: expectedWrapped
            )
        } else {
            assertNegativeVector(
                vector: vector,
                materials: materials,
                expectedWrapped: expectedWrapped
            )
        }
    }

    func resolveMaterials(_ vector: EcdhWrapVector) throws -> VectorMaterials {
        let snapshotKeyBytes = try hexToData(vector.inputs.snapshotKeyHex)
        let senderPriv = try P256.KeyAgreement.PrivateKey(
            pemRepresentation: vector.inputs.senderPrivateKeyPkcs8Pem
        )
        let recipientPriv = try P256.KeyAgreement.PrivateKey(
            pemRepresentation: vector.inputs.recipientPrivateKeyPkcs8Pem
        )
        let recipientPubRaw = try hexToData(vector.inputs.recipientPublicKeyUncompressedHex)
        let nonceBytes = try hexToData(vector.inputs.aeadNonceHex)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let shared = try KeyWrap.sharedSecretBytes(
            localPrivate: senderPriv,
            peerPublic: recipientPriv.publicKey
        )
        return VectorMaterials(
            snapshotId: vector.inputs.snapshotId,
            snapshotKey: SymmetricKey(data: snapshotKeyBytes),
            snapshotKeyBytes: snapshotKeyBytes,
            senderPriv: senderPriv,
            recipientPriv: recipientPriv,
            recipientPubRaw: recipientPubRaw,
            nonce: nonce,
            sharedSecret: shared
        )
    }

    func assertIntermediates(vector: EcdhWrapVector, materials: VectorMaterials) {
        XCTAssertEqual(
            hexString(materials.sharedSecret),
            vector.expected.sharedSecretHex,
            "vector \(vector.name): shared secret mismatch"
        )
        let info = (try? KeyWrap.buildHkdfInfo(
            snapshotId: materials.snapshotId,
            recipientPubRaw: materials.recipientPubRaw
        )) ?? Data()
        XCTAssertEqual(
            hexString(info),
            vector.expected.hkdfInfoHex,
            "vector \(vector.name): hkdf info mismatch"
        )
        let aad = (try? KeyWrap.buildAad(snapshotId: materials.snapshotId)) ?? Data()
        XCTAssertEqual(
            hexString(aad),
            vector.expected.hkdfAadHex,
            "vector \(vector.name): hkdf aad mismatch"
        )
        let wrappingKey = (try? KeyWrap.deriveWrappingKey(
            sharedSecret: materials.sharedSecret,
            snapshotId: materials.snapshotId,
            recipientPubRaw: materials.recipientPubRaw
        )) ?? SymmetricKey(size: .bits256)
        XCTAssertEqual(
            hexString(wrappingKey.withUnsafeBytes { Data($0) }),
            vector.expected.wrappingKeyHex,
            "vector \(vector.name): wrapping key mismatch"
        )
    }

    func assertPositiveVector(
        vector: EcdhWrapVector,
        materials: VectorMaterials,
        expectedWrapped: Data
    ) throws {
        let wrapped = try KeyWrap.wrapWithFixedNonce(
            snapshotKey: materials.snapshotKey,
            ownerPrivate: materials.senderPriv,
            recipientPublic: AgreementPublicKey(materials.recipientPriv.publicKey),
            snapshotId: materials.snapshotId,
            nonce: materials.nonce
        )
        XCTAssertEqual(
            hexString(wrapped),
            vector.expected.wrappedKeyHex,
            "vector \(vector.name): wrapped output mismatch"
        )
        let recovered = try KeyWrap.unwrap(
            expectedWrapped,
            recipientPrivate: materials.recipientPriv,
            ownerPublic: AgreementPublicKey(materials.senderPriv.publicKey),
            snapshotId: materials.snapshotId
        )
        XCTAssertEqual(
            recovered.withUnsafeBytes { Data($0) },
            materials.snapshotKeyBytes,
            "vector \(vector.name): unwrap did not recover snapshot key"
        )
    }

    func assertNegativeVector(
        vector: EcdhWrapVector,
        materials: VectorMaterials,
        expectedWrapped: Data
    ) {
        XCTAssertThrowsError(
            try KeyWrap.unwrap(
                expectedWrapped,
                recipientPrivate: materials.recipientPriv,
                ownerPublic: AgreementPublicKey(materials.senderPriv.publicKey),
                snapshotId: materials.snapshotId
            ),
            "vector \(vector.name) expected to throw on unwrap"
        ) { error in
            guard case .aead = error as? CryptoError else {
                XCTFail("vector \(vector.name): expected .aead, got \(error)")
                return
            }
        }
    }
}

// MARK: - Shared test helpers used by KeyWrapTests

extension KeyWrapTests {

    struct WrappedBytes {
        var wrapped: Data
        let snapshotKey: SymmetricKey
        let owner: P256.KeyAgreement.PrivateKey
        let recipient: P256.KeyAgreement.PrivateKey
        let snapshotId: String
    }

    struct WrappedFixture {
        var bytes: WrappedBytes
    }

    func makeWrapped(snapshotId: String = "snap-fixture") throws -> WrappedFixture {
        let snapshotKey = SymmetricKey(size: .bits256)
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()
        let wrapped = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(recipient.publicKey),
            snapshotId: snapshotId
        )
        return WrappedFixture(bytes: WrappedBytes(
            wrapped: wrapped,
            snapshotKey: snapshotKey,
            owner: owner,
            recipient: recipient,
            snapshotId: snapshotId
        ))
    }

    func rawBytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    func assertAead(
        _ error: Error,
        contains needle: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .aead(let reason) = error as? CryptoError else {
            XCTFail("expected .aead, got \(error)", file: file, line: line)
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

// MARK: - File-scope helpers

enum HexDecodeError: Error { case oddLength, invalidCharacter }

func hexToData(_ hex: String) throws -> Data {
    guard hex.count.isMultiple(of: 2) else { throw HexDecodeError.oddLength }
    var out = Data(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            throw HexDecodeError.invalidCharacter
        }
        out.append(byte)
        index = next
    }
    return out
}

func hexString(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

// MARK: - Fixture schema

struct EcdhWrapVector: Decodable {
    let name: String
    let inputs: Inputs
    let expected: Expected
    let valid: Bool

    struct Inputs: Decodable {
        let snapshotId: String
        let snapshotKeyHex: String
        let senderPrivateKeyPkcs8Pem: String
        let senderPublicKeyUncompressedHex: String
        let recipientPrivateKeyPkcs8Pem: String
        let recipientPublicKeyUncompressedHex: String
        let aeadNonceHex: String

        enum CodingKeys: String, CodingKey {
            case snapshotId = "snapshot_id"
            case snapshotKeyHex = "snapshot_key_hex"
            case senderPrivateKeyPkcs8Pem = "sender_private_key_pkcs8_pem"   // pragma: allowlist secret
            case senderPublicKeyUncompressedHex = "sender_public_key_uncompressed_hex"
            case recipientPrivateKeyPkcs8Pem = "recipient_private_key_pkcs8_pem"   // pragma: allowlist secret
            case recipientPublicKeyUncompressedHex = "recipient_public_key_uncompressed_hex"
            case aeadNonceHex = "aead_nonce_hex"
        }
    }

    struct Expected: Decodable {
        let sharedSecretHex: String
        let hkdfInfoHex: String
        let hkdfAadHex: String
        let wrappingKeyHex: String
        let wrappedKeyHex: String

        enum CodingKeys: String, CodingKey {
            case sharedSecretHex = "shared_secret_hex"   // pragma: allowlist secret
            case hkdfInfoHex = "hkdf_info_hex"
            case hkdfAadHex = "hkdf_aad_hex"
            case wrappingKeyHex = "wrapping_key_hex"
            case wrappedKeyHex = "wrapped_key_hex"
        }
    }
}
