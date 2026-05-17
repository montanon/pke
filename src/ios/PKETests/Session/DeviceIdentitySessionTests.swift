// Coverage for `DeviceIdentitySession` — the @MainActor wrapper around
// HLAM-2's `DeviceIdentityService`. Tests run against `InMemoryKeychainFake`
// (symlinked from `PKETests/Identity/`) so no real Keychain access is needed.
//
// What's covered:
//   * AC 1 — cold-start identity generation, keychain attributes via HLAM-2
//   * AC 2 — relaunch returns same key bytes, no extra writes
//   * AC 3 — public keys are 65-byte uncompressed P-256 (`0x04 || X || Y`)
//   * AC 4 — `sign(_:)` returns 64-byte raw P1363 verifiable by the pubkey
//   * AC 5 — `unwrap(grant:...)` happy path + every error mapping
//   * AC 6 — implicit: every test runs against the Keychain mock
//   * AC 7 — public API surface contains no private-key accessor
//
// What's NOT covered here (by design, see Testing Plan comment):
//   * `DeviceIdentitySession.shared` — requires a real entitled Keychain
//   * cross-language vector parity — already covered by `PKECryptoTests`

#if canImport(Security)
import XCTest
import enum Crypto.P256
import struct Crypto.SymmetricKey

import PKECrypto
@testable import PKEIdentity
import PKEProtocol
@testable import PKESession

@MainActor
final class DeviceIdentitySessionTests: XCTestCase {

    // MARK: - AC 1: cold start

    func testColdStartGeneratesIdentity() throws {
        let keychain = InMemoryKeychainFake()
        let session = try makeSession(keychain: keychain)

        let stored = keychain.snapshot()
        XCTAssertEqual(stored.count, 2)
        XCTAssertNotNil(stored[IdentityLabels.signingTag])
        XCTAssertNotNil(stored[IdentityLabels.agreementTag])
        XCTAssertEqual(keychain.setCalls.count, 2)
        XCTAssertEqual(
            Set(keychain.setCalls.map(\.label)),
            [IdentityLabels.signingTag, IdentityLabels.agreementTag]
        )
        // Side effect proven: pubkeys are well-formed (covered by AC-3 tests).
        XCTAssertEqual(session.signingPublicKey.count, 65)
    }

    // MARK: - AC 2: relaunch idempotency

    func testRelaunchReturnsSameKeyBytes() throws {
        let keychain = InMemoryKeychainFake()
        let first = try makeSession(keychain: keychain)
        let signingBefore = first.signingPublicKey
        let encryptionBefore = first.encryptionPublicKey

        // Simulate a relaunch: a second session over the same backing store.
        let second = try makeSession(keychain: keychain)

        XCTAssertEqual(second.signingPublicKey, signingBefore)
        XCTAssertEqual(second.encryptionPublicKey, encryptionBefore)
        // No new writes — only the cold-start pair.
        XCTAssertEqual(keychain.setCalls.count, 2)
    }

    // MARK: - AC 3: pubkey format

    func testSigningPublicKeyIs65ByteUncompressed() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let pub = session.signingPublicKey
        XCTAssertEqual(pub.count, 65)
        XCTAssertEqual(pub.first, 0x04, "expected SEC1 uncompressed tag byte")
    }

    func testEncryptionPublicKeyIs65ByteUncompressed() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let pub = session.encryptionPublicKey
        XCTAssertEqual(pub.count, 65)
        XCTAssertEqual(pub.first, 0x04, "expected SEC1 uncompressed tag byte")
    }

    // MARK: - AC 4: sign

    func testSignProducesP1363SignatureVerifiableByPublicKey() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let payload = Data("payload".utf8)

        let signature = try session.sign(payload)
        XCTAssertEqual(signature.count, 64, "expected raw P1363 r||s")

        let publicKey = try P256.Signing.PublicKey(
            x963Representation: session.signingPublicKey
        )
        XCTAssertNoThrow(try Signatures.verify(signature, of: payload, by: publicKey))
    }

    func testSignAcceptsEmptyPayload() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let signature = try session.sign(Data())
        XCTAssertEqual(signature.count, 64)

        let publicKey = try P256.Signing.PublicKey(
            x963Representation: session.signingPublicKey
        )
        XCTAssertNoThrow(try Signatures.verify(signature, of: Data(), by: publicKey))
    }

    // MARK: - AC 5: unwrap

    func testUnwrapRoundTripRecoversSnapshotKey() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let owner = makeOwnerIdentity()
        let snapshotId = "snap-roundtrip-001"
        let snapshotKey = SymmetricKey(size: .bits256)

        let grant = try makeGrant(
            snapshotKey: snapshotKey,
            recipientEncryptionPublicKey: session.encryptionPublicKey,
            owner: owner,
            snapshotId: snapshotId
        )

        let recovered = try session.unwrap(
            grant: grant,
            ownerAgreementPublicKey: AgreementPublicKey(owner.agreement.publicKey)
        )

        XCTAssertEqual(
            recovered.withUnsafeBytes { Data($0) },
            snapshotKey.withUnsafeBytes { Data($0) }
        )
    }

    func testUnwrapRejectsUnsupportedAlgorithm() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let owner = makeOwnerIdentity()
        let grant = try makeGrant(
            snapshotKey: SymmetricKey(size: .bits256),
            recipientEncryptionPublicKey: session.encryptionPublicKey,
            owner: owner,
            snapshotId: "snap-bad-algo",
            wrappingAlgorithm: "rsa-oaep-2048"
        )

        XCTAssertThrowsError(
            try session.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(owner.agreement.publicKey)
            )
        ) { error in
            XCTAssertEqual(error as? UnwrapError, .unsupportedAlgorithm("rsa-oaep-2048"))
        }
    }

    func testUnwrapRejectsWhenRecipientPubkeyMismatches() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let owner = makeOwnerIdentity()
        // Recipient pubkey on the grant is some OTHER device's pubkey.
        let foreignRecipient = P256.KeyAgreement.PrivateKey().publicKey
        let grant = try makeGrant(
            snapshotKey: SymmetricKey(size: .bits256),
            recipientEncryptionPublicKey: Data(foreignRecipient.x963Representation),
            owner: owner,
            snapshotId: "snap-wrong-recipient"
        )

        XCTAssertThrowsError(
            try session.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(owner.agreement.publicKey)
            )
        ) { error in
            XCTAssertEqual(error as? UnwrapError, .recipientMismatch)
        }
    }

    func testUnwrapMapsAeadErrorOnTamperedCiphertext() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let owner = makeOwnerIdentity()
        var grant = try makeGrant(
            snapshotKey: SymmetricKey(size: .bits256),
            recipientEncryptionPublicKey: session.encryptionPublicKey,
            owner: owner,
            snapshotId: "snap-tampered"
        )

        // Flip one bit deep inside the ciphertext region (offset 20 is in the
        // 12..<44 ciphertext slice of the 60-byte wrap blob).
        var tampered = grant.wrappedSnapshotKey
        tampered[20] ^= 0x01
        grant = KeyGrant(
            version: grant.version,
            grantId: grant.grantId,
            snapshotId: grant.snapshotId,
            recipientEncryptionPublicKey: grant.recipientEncryptionPublicKey,
            wrappedSnapshotKey: tampered,
            wrappingAlgorithm: grant.wrappingAlgorithm,
            grantedBySigningPublicKey: grant.grantedBySigningPublicKey,
            grantTimestamp: grant.grantTimestamp,
            grantSignature: grant.grantSignature
        )

        XCTAssertThrowsError(
            try session.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(owner.agreement.publicKey)
            )
        ) { error in
            guard case .aead(let reason) = error as? UnwrapError else {
                XCTFail("expected UnwrapError.aead, got \(error)")
                return
            }
            XCTAssertFalse(reason.isEmpty)
        }
    }

    func testUnwrapMapsAeadErrorOnWrongOwnerAgreementKey() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let owner = makeOwnerIdentity()
        let grant = try makeGrant(
            snapshotKey: SymmetricKey(size: .bits256),
            recipientEncryptionPublicKey: session.encryptionPublicKey,
            owner: owner,
            snapshotId: "snap-wrong-owner-pub"
        )

        // A different owner pubkey at unwrap time → ECDH derives a different
        // shared secret → AEAD tag will not verify.
        let imposterOwnerAgreement = P256.KeyAgreement.PrivateKey().publicKey

        XCTAssertThrowsError(
            try session.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(imposterOwnerAgreement)
            )
        ) { error in
            guard case .aead = error as? UnwrapError else {
                XCTFail("expected UnwrapError.aead, got \(error)")
                return
            }
        }
    }

    func testUnwrapMapsAeadErrorOnMalformedWrappedBlob() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let owner = makeOwnerIdentity()
        // Valid algorithm + matching recipient pubkey, but the wrap blob is
        // under-sized — KeyWrap's length gate fires before any crypto math.
        let undersized = Data(count: 10)
        let grant = KeyGrant(
            version: "0.1",
            grantId: "grant-malformed-blob",
            snapshotId: "snap-malformed",
            recipientEncryptionPublicKey: session.encryptionPublicKey,
            wrappedSnapshotKey: undersized,
            wrappingAlgorithm: "ecdhp256+aesgcm256",
            grantedBySigningPublicKey: Data(owner.signing.publicKey.x963Representation),
            grantTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 0)),
            grantSignature: Data(count: 64)
        )

        XCTAssertThrowsError(
            try session.unwrap(
                grant: grant,
                ownerAgreementPublicKey: AgreementPublicKey(owner.agreement.publicKey)
            )
        ) { error in
            guard case .aead(let reason) = error as? UnwrapError else {
                XCTFail("expected UnwrapError.aead, got \(error)")
                return
            }
            XCTAssertTrue(
                reason.contains("60"),
                "expected reason to reference the 60-byte expected length, got: \(reason)"
            )
        }
    }

    // MARK: - AC 1: keychain failure propagation

    func testKeychainInitFailurePropagates() throws {
        let keychain = InMemoryKeychainFake()
        let injected = CryptoError.keychain(reason: "OSStatus: -25291")
        keychain.failNext(.get, for: IdentityLabels.signingTag, with: injected)

        XCTAssertThrowsError(try makeSession(keychain: keychain)) { error in
            XCTAssertEqual(error as? CryptoError, injected)
        }
    }

    func testKeychainHalfStateRollbackPropagates() throws {
        let keychain = InMemoryKeychainFake()
        let injected = CryptoError.keychain(reason: "OSStatus: -25300")
        keychain.failNext(.set, for: IdentityLabels.agreementTag, with: injected)

        XCTAssertThrowsError(try makeSession(keychain: keychain)) { error in
            XCTAssertEqual(error as? CryptoError, injected)
        }
        // HLAM-8 rollback contract still holds through the wrapper.
        XCTAssertTrue(keychain.snapshot().isEmpty, "expected rollback of signing key write")
        XCTAssertEqual(keychain.deleteCalls, [IdentityLabels.signingTag])
    }

    // MARK: - AC 7: public API surface
    //
    // Mirror reflection only enumerates STORED properties, so this guard
    // catches the foot-gun of someone adding a public stored `signingKey:` /
    // `agreementKey:` property. It does NOT catch a future `var signingKey:
    // P256.Signing.PrivateKey { identity.signingKey }` computed accessor —
    // that has to be caught at code review. Definition-of-done requires the
    // PR be reviewed by someone who has touched HLAM-2's `PKEIdentity`.

    func testStoredPropertiesDoNotIncludePrivateKey() throws {
        let session = try makeSession(keychain: InMemoryKeychainFake())
        let labels = Mirror(reflecting: session).children.compactMap(\.label)
        XCTAssertFalse(labels.contains("signingKey"))
        XCTAssertFalse(labels.contains("agreementKey"))
        XCTAssertFalse(labels.contains("signingPrivateKey"))
        XCTAssertFalse(labels.contains("agreementPrivateKey"))
    }

    // MARK: - Helpers

    private func makeSession(keychain: InMemoryKeychainFake) throws -> DeviceIdentitySession {
        try DeviceIdentitySession(service: DeviceIdentityService(keychain: keychain))
    }

    private struct OwnerIdentity {
        let signing: P256.Signing.PrivateKey
        let agreement: P256.KeyAgreement.PrivateKey
    }

    private func makeOwnerIdentity() -> OwnerIdentity {
        OwnerIdentity(
            signing: P256.Signing.PrivateKey(),
            agreement: P256.KeyAgreement.PrivateKey()
        )
    }

    private func makeGrant(
        snapshotKey: SymmetricKey,
        recipientEncryptionPublicKey: Data,
        owner: OwnerIdentity,
        snapshotId: String,
        wrappingAlgorithm: String = "ecdhp256+aesgcm256"
    ) throws -> KeyGrant {
        // Build a valid wrap blob with the owner -> recipient ECDH path.
        // For the unsupported-algorithm test, the algorithm string is the
        // gate that fires — the blob itself doesn't have to be cryptographically
        // matched to that algorithm.
        let recipientAgreement = try AgreementPublicKey(
            P256.KeyAgreement.PublicKey(x963Representation: recipientEncryptionPublicKey)
        )
        let wrapped = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner.agreement,
            recipientPublic: recipientAgreement,
            snapshotId: snapshotId
        )
        return KeyGrant(
            version: "0.1",
            grantId: "grant-\(UUID().uuidString)",
            snapshotId: snapshotId,
            recipientEncryptionPublicKey: recipientEncryptionPublicKey,
            wrappedSnapshotKey: wrapped,
            wrappingAlgorithm: wrappingAlgorithm,
            grantedBySigningPublicKey: Data(owner.signing.publicKey.x963Representation),
            grantTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 0)),
            grantSignature: Data(count: 64)
        )
    }
}
#endif
