// Unit tests for `SnapshotDecryptionService` (HLAM-118).
//
// Strategy: inject closures wired to `KeyWrap.unwrap` (real ECDH+HKDF+AES-GCM)
// and `AEAD.seal`/`AEAD.open` so the AC #7 byte-identity property gets
// exercised on the same primitives the production composition root uses,
// while the error-mapping branches (CryptoError.aead, generic Error,
// already-typed DecryptionError) get exercised with synthetic closures.
//
// The shared vector corpus drives `SnapshotDecryptionServiceVectorTests`
// (separate file). This file covers the service's own contract:
// happy-path, tamper, length-gate, error mapping, and AC #6's no-stored-key
// invariant.

import XCTest
import struct Crypto.SymmetricKey
import enum Crypto.P256
import enum Crypto.AES
@testable import PKECrypto
@testable import PKEProtocol
@testable import PKERecipient

final class SnapshotDecryptionServiceTests: XCTestCase {

    // MARK: - Fixtures

    private struct Fixture {
        let snapshotKey: SymmetricKey
        let snapshotId: String
        let ownerAgreement: P256.KeyAgreement.PrivateKey
        let recipientAgreement: P256.KeyAgreement.PrivateKey
        let wrapped: Data
    }

    private func makeFixture() throws -> Fixture {
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()
        let snapshotKey = SymmetricKey(size: .bits256)
        let snapshotId = "snap-test"
        let wrapped = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(recipient.publicKey),
            snapshotId: snapshotId
        )
        return Fixture(
            snapshotKey: snapshotKey,
            snapshotId: snapshotId,
            ownerAgreement: owner,
            recipientAgreement: recipient,
            wrapped: wrapped
        )
    }

    private func makeGrant(
        wrapped: Data,
        snapshotId: String,
        recipientPubRaw: Data,
        ownerSigningPubRaw: Data = Data(repeating: 0x04, count: 65)
    ) -> KeyGrant {
        KeyGrant(
            version: "0.1",
            grantId: "grant-test",
            snapshotId: snapshotId,
            recipientEncryptionPublicKey: recipientPubRaw,
            wrappedSnapshotKey: wrapped,
            wrappingAlgorithm: "ecdhp256+aesgcm256",
            grantedBySigningPublicKey: ownerSigningPubRaw,
            grantTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 1_700_000_000)),
            grantSignature: Data(repeating: 0xFE, count: 64)
        )
    }

    /// Build a service whose `UnwrapClosure` invokes `KeyWrap.unwrap` with
    /// the recipient private key from the test fixture. The owner agreement
    /// public key supplied at the call site is the same one the test
    /// originally wrapped with.
    private func makeService(recipient: P256.KeyAgreement.PrivateKey) -> SnapshotDecryptionService {
        SnapshotDecryptionService(unwrap: { grant, ownerPub in
            try KeyWrap.unwrap(
                grant.wrappedSnapshotKey,
                recipientPrivate: recipient,
                ownerPublic: ownerPub,
                snapshotId: grant.snapshotId
            )
        })
    }

    private func rawBytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    // MARK: - AC #1 — happy path

    func test_unwrap_returns32ByteSnapshotKey_onValidGrant() throws {
        let fix = try makeFixture()
        let service = makeService(recipient: fix.recipientAgreement)
        let grant = makeGrant(
            wrapped: fix.wrapped,
            snapshotId: fix.snapshotId,
            recipientPubRaw: Data(fix.recipientAgreement.publicKey.x963Representation)
        )

        let recovered = try service.unwrap(
            grant: grant,
            ownerAgreementPublicKey: AgreementPublicKey(fix.ownerAgreement.publicKey)
        )

        XCTAssertEqual(rawBytes(recovered), rawBytes(fix.snapshotKey))
        XCTAssertEqual(rawBytes(recovered).count, 32)
    }

    // MARK: - AC #2 — tampered wrapped key

    func test_unwrap_throwsUnwrapFailed_onTamperedWrappedSnapshotKey() throws {
        let fix = try makeFixture()
        var tampered = fix.wrapped
        // Flip a byte in the ciphertext region (offset 12..<44 per KeyWrap layout).
        tampered[32] ^= 0x01

        let service = makeService(recipient: fix.recipientAgreement)
        let grant = makeGrant(
            wrapped: tampered,
            snapshotId: fix.snapshotId,
            recipientPubRaw: Data(fix.recipientAgreement.publicKey.x963Representation)
        )

        do {
            _ = try service.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(fix.ownerAgreement.publicKey)
            )
            XCTFail("expected unwrapFailed")
        } catch let DecryptionError.unwrapFailed(reason) {
            XCTAssertTrue(reason.contains("tag"), "reason: \(reason)")
        } catch {
            XCTFail("expected DecryptionError.unwrapFailed, got \(error)")
        }
    }

    // MARK: - AC #3 — tampered AAD context (snapshot_id mismatch)

    func test_unwrap_throwsUnwrapFailed_onMismatchedSnapshotIdAAD() throws {
        let fix = try makeFixture()
        let service = makeService(recipient: fix.recipientAgreement)
        let grant = makeGrant(
            wrapped: fix.wrapped,
            snapshotId: "different-snapshot-id",
            recipientPubRaw: Data(fix.recipientAgreement.publicKey.x963Representation)
        )

        do {
            _ = try service.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(fix.ownerAgreement.publicKey)
            )
            XCTFail("expected unwrapFailed (AAD mismatch)")
        } catch let DecryptionError.unwrapFailed(reason) {
            XCTAssertTrue(reason.contains("tag"), "reason: \(reason)")
        } catch {
            XCTFail("expected DecryptionError.unwrapFailed, got \(error)")
        }
    }

    // MARK: - Error mapping

    func test_unwrap_propagatesDecryptionErrorFromClosure() throws {
        let service = SnapshotDecryptionService(unwrap: { _, _ in
            throw DecryptionError.unsupportedAlgorithm("future-alg")
        })
        let grant = makeGrant(
            wrapped: Data(repeating: 0, count: 60),
            snapshotId: "x",
            recipientPubRaw: Data(repeating: 0x04, count: 65)
        )
        let dummyOwner = P256.KeyAgreement.PrivateKey()
        do {
            _ = try service.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(dummyOwner.publicKey)
            )
            XCTFail("expected unsupportedAlgorithm to surface")
        } catch DecryptionError.unsupportedAlgorithm(let name) {
            XCTAssertEqual(name, "future-alg")
        } catch {
            XCTFail("expected DecryptionError.unsupportedAlgorithm, got \(error)")
        }
    }

    func test_unwrap_mapsCryptoErrorAead_toUnwrapFailed() throws {
        let service = SnapshotDecryptionService(unwrap: { _, _ in
            throw CryptoError.aead(reason: "synthetic tag failure")
        })
        let grant = makeGrant(
            wrapped: Data(repeating: 0, count: 60),
            snapshotId: "x",
            recipientPubRaw: Data(repeating: 0x04, count: 65)
        )
        let dummyOwner = P256.KeyAgreement.PrivateKey()
        do {
            _ = try service.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(dummyOwner.publicKey)
            )
            XCTFail("expected unwrapFailed")
        } catch DecryptionError.unwrapFailed(let reason) {
            XCTAssertEqual(reason, "synthetic tag failure")
        } catch {
            XCTFail("got \(error)")
        }
    }

    func test_unwrap_mapsUnknownErrors_toUnwrapFailed() throws {
        struct StubError: Error, CustomStringConvertible {
            var description: String { "stub-failure" }
        }
        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError() })
        let grant = makeGrant(
            wrapped: Data(repeating: 0, count: 60),
            snapshotId: "x",
            recipientPubRaw: Data(repeating: 0x04, count: 65)
        )
        let dummyOwner = P256.KeyAgreement.PrivateKey()
        do {
            _ = try service.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(dummyOwner.publicKey)
            )
            XCTFail("expected unwrapFailed")
        } catch DecryptionError.unwrapFailed(let reason) {
            XCTAssertTrue(reason.contains("stub-failure"), "reason: \(reason)")
        } catch {
            XCTFail("got \(error)")
        }
    }

    // MARK: - AC #6 — service stores no snapshot key

    func test_unwrap_serviceStoresNoSnapshotKey() {
        let service = SnapshotDecryptionService(unwrap: { _, _ in SymmetricKey(size: .bits256) })
        let mirror = Mirror(reflecting: service)
        for child in mirror.children {
            // The only stored property is the closure; nothing of type
            // SymmetricKey, Data, or anything that could hold a snapshot key.
            XCTAssertFalse(child.value is SymmetricKey, "found SymmetricKey field: \(child.label ?? "?")")
            XCTAssertFalse(child.value is Data, "found Data field: \(child.label ?? "?")")
        }
    }

    // MARK: - AC #4 — decrypt happy path

    func test_decrypt_returnsPlaintext_onValidCiphertext() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("hello world".utf8)
        let nonce = Data(repeating: 0xAB, count: 12)
        let sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: Data())

        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError.unreachable })
        let recovered = try service.decrypt(snapshotKey: key, ciphertext: sealed, aad: Data())
        XCTAssertEqual(recovered, plaintext)
    }

    func test_decrypt_succeedsWithEmptyAAD() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data([0x01, 0x02, 0x03])
        let nonce = Data(repeating: 0xCC, count: 12)
        let sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: Data())

        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError.unreachable })
        let recovered = try service.decrypt(snapshotKey: key, ciphertext: sealed, aad: Data())
        XCTAssertEqual(recovered, plaintext)
    }

    // MARK: - AC #5 — decrypt tamper cases

    func test_decrypt_throwsDecryptFailed_onTamperedCiphertext() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data(repeating: 0x42, count: 32)
        let nonce = Data(repeating: 0xDD, count: 12)
        var sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: Data())
        // Flip a ciphertext byte (between nonce and tag).
        sealed[15] ^= 0x01

        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError.unreachable })
        do {
            _ = try service.decrypt(snapshotKey: key, ciphertext: sealed, aad: Data())
            XCTFail("expected decryptFailed")
        } catch DecryptionError.decryptFailed(let reason) {
            XCTAssertTrue(reason.contains("open") || reason.contains("tag"), "reason: \(reason)")
        } catch {
            XCTFail("got \(error)")
        }
    }

    func test_decrypt_throwsDecryptFailed_onTamperedTag() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data(repeating: 0x37, count: 24)
        let nonce = Data(repeating: 0xEE, count: 12)
        var sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: Data())
        // Flip a byte in the trailing tag.
        sealed[sealed.count - 4] ^= 0x01

        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError.unreachable })
        XCTAssertThrowsError(try service.decrypt(snapshotKey: key, ciphertext: sealed, aad: Data())) { error in
            guard case DecryptionError.decryptFailed = error else {
                XCTFail("expected decryptFailed, got \(error)")
                return
            }
        }
    }

    func test_decrypt_throwsDecryptFailed_onWrongAAD() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("payload".utf8)
        let nonce = Data(repeating: 0x11, count: 12)
        let sealed = try AEAD.seal(plaintext: plaintext, key: key, nonce: nonce, aad: Data("a".utf8))

        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError.unreachable })
        XCTAssertThrowsError(try service.decrypt(snapshotKey: key, ciphertext: sealed, aad: Data("b".utf8))) { error in
            guard case DecryptionError.decryptFailed = error else {
                XCTFail("expected decryptFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Edge case — malformed ciphertext (<28 bytes)

    func test_decrypt_throwsMalformedCiphertext_below28Bytes() throws {
        let key = SymmetricKey(size: .bits256)
        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError.unreachable })
        XCTAssertThrowsError(try service.decrypt(snapshotKey: key, ciphertext: Data(repeating: 0, count: 27), aad: Data())) { error in
            guard case DecryptionError.malformedCiphertext(let byteCount) = error else {
                XCTFail("expected malformedCiphertext, got \(error)")
                return
            }
            XCTAssertEqual(byteCount, 27)
        }
    }

    func test_decrypt_throwsMalformedCiphertext_atZeroBytes() throws {
        let key = SymmetricKey(size: .bits256)
        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError.unreachable })
        XCTAssertThrowsError(try service.decrypt(snapshotKey: key, ciphertext: Data(), aad: Data())) { error in
            guard case DecryptionError.malformedCiphertext(let byteCount) = error else {
                XCTFail("expected malformedCiphertext, got \(error)")
                return
            }
            XCTAssertEqual(byteCount, 0)
        }
    }

    func test_decrypt_28ByteEmptyPlaintext_returnsEmpty() throws {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x55, count: 12)
        let sealed = try AEAD.seal(plaintext: Data(), key: key, nonce: nonce, aad: Data())
        XCTAssertEqual(sealed.count, 28)

        let service = SnapshotDecryptionService(unwrap: { _, _ in throw StubError.unreachable })
        let recovered = try service.decrypt(snapshotKey: key, ciphertext: sealed, aad: Data())
        XCTAssertEqual(recovered, Data())
    }
}

private enum StubError: Error {
    case unreachable
}
