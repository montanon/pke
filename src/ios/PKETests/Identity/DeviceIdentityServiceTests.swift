// Coverage for `DeviceIdentityService.loadOrCreate()` — the 6-step
// half-state-recovery algorithm from HLAM-8. Exercises cold start, warm
// start (idempotency), both half-state directions, the second-write-failure
// rollback path, and the malformed-bytes path. Linux skips the whole file
// via `#if canImport(Security)`.

#if canImport(Security)
import XCTest
// Import only the swift-crypto symbols we need so the `Crypto.CryptoError`
// typealias does not collide with `PKECrypto.CryptoError` in this file.
import enum Crypto.P256

@testable import PKEIdentity
import PKECrypto

final class DeviceIdentityServiceTests: XCTestCase {

    // MARK: AC 1 — cold start

    func testColdStartGeneratesAndPersistsBothKeys() throws {
        let keychain = InMemoryKeychainFake()
        let service = DeviceIdentityService(keychain: keychain)

        let identity = try service.loadOrCreate()

        let stored = keychain.snapshot()
        XCTAssertEqual(stored.count, 2)
        XCTAssertEqual(
            stored[IdentityLabels.signingTag],
            identity.signingKey.rawRepresentation
        )
        XCTAssertEqual(
            stored[IdentityLabels.agreementTag],
            identity.agreementKey.rawRepresentation
        )
    }

    // MARK: AC 2 — idempotent

    func testSecondCallReturnsSameKeyBytes() throws {
        let keychain = InMemoryKeychainFake()
        let service = DeviceIdentityService(keychain: keychain)

        let first = try service.loadOrCreate()
        let second = try service.loadOrCreate()

        XCTAssertEqual(
            first.signingKey.rawRepresentation,
            second.signingKey.rawRepresentation
        )
        XCTAssertEqual(
            first.agreementKey.rawRepresentation,
            second.agreementKey.rawRepresentation
        )
        // Second call must NOT write again.
        XCTAssertEqual(keychain.setCalls.count, 2)
    }

    // MARK: AC 3 — half-state: only signing present

    func testHalfStateGeneratesAgreementWhenOnlySigningPresent() throws {
        let preexistingSigning = P256.Signing.PrivateKey()
        let keychain = InMemoryKeychainFake(preloaded: [
            IdentityLabels.signingTag: preexistingSigning.rawRepresentation
        ])
        let service = DeviceIdentityService(keychain: keychain)

        let identity = try service.loadOrCreate()

        XCTAssertEqual(
            identity.signingKey.rawRepresentation,
            preexistingSigning.rawRepresentation
        )
        let stored = keychain.snapshot()
        XCTAssertEqual(
            stored[IdentityLabels.agreementTag],
            identity.agreementKey.rawRepresentation
        )
        XCTAssertEqual(keychain.setCalls.count, 1)
        XCTAssertEqual(keychain.setCalls.first?.label, IdentityLabels.agreementTag)
    }

    // MARK: AC 4 — half-state: only agreement present

    func testHalfStateGeneratesSigningWhenOnlyAgreementPresent() throws {
        let preexistingAgreement = P256.KeyAgreement.PrivateKey()
        let keychain = InMemoryKeychainFake(preloaded: [
            IdentityLabels.agreementTag: preexistingAgreement.rawRepresentation
        ])
        let service = DeviceIdentityService(keychain: keychain)

        let identity = try service.loadOrCreate()

        XCTAssertEqual(
            identity.agreementKey.rawRepresentation,
            preexistingAgreement.rawRepresentation
        )
        let stored = keychain.snapshot()
        XCTAssertEqual(
            stored[IdentityLabels.signingTag],
            identity.signingKey.rawRepresentation
        )
        XCTAssertEqual(keychain.setCalls.count, 1)
        XCTAssertEqual(keychain.setCalls.first?.label, IdentityLabels.signingTag)
    }

    // MARK: AC 5 — second-write failure triggers best-effort rollback

    func testColdStartRollsBackSigningWhenAgreementWriteFails() throws {
        let keychain = InMemoryKeychainFake()
        let injected = CryptoError.keychain(reason: "OSStatus: -25300")
        keychain.failNext(.set, for: IdentityLabels.agreementTag, with: injected)
        let service = DeviceIdentityService(keychain: keychain)

        XCTAssertThrowsError(try service.loadOrCreate()) { error in
            XCTAssertEqual(error as? CryptoError, injected)
        }
        XCTAssertTrue(keychain.snapshot().isEmpty, "Signing write should be rolled back")
        XCTAssertEqual(keychain.deleteCalls, [IdentityLabels.signingTag])
    }

    func testRollbackDeleteFailureDoesNotMaskOriginalError() throws {
        let keychain = InMemoryKeychainFake()
        let writeError = CryptoError.keychain(reason: "OSStatus: -25300")
        let cleanupError = CryptoError.keychain(reason: "OSStatus: -25308")
        keychain.failNext(.set, for: IdentityLabels.agreementTag, with: writeError)
        keychain.failNext(.delete, for: IdentityLabels.signingTag, with: cleanupError)
        let service = DeviceIdentityService(keychain: keychain)

        XCTAssertThrowsError(try service.loadOrCreate()) { error in
            XCTAssertEqual(
                error as? CryptoError,
                writeError,
                "Cleanup failure must not mask the original write failure"
            )
        }
    }

    // MARK: AC 6 — malformed bytes

    func testMalformedSigningBytesRaiseIdentityError() throws {
        let keychain = InMemoryKeychainFake(preloaded: [
            IdentityLabels.signingTag: Data(repeating: 0xFF, count: 7),
            IdentityLabels.agreementTag: P256.KeyAgreement.PrivateKey().rawRepresentation
        ])
        let service = DeviceIdentityService(keychain: keychain)

        XCTAssertThrowsError(try service.loadOrCreate()) { error in
            XCTAssertEqual(
                error as? CryptoError,
                .identity(reason: "keychain returned malformed key bytes")
            )
        }
    }

    func testMalformedAgreementBytesRaiseIdentityError() throws {
        let keychain = InMemoryKeychainFake(preloaded: [
            IdentityLabels.signingTag: P256.Signing.PrivateKey().rawRepresentation,
            IdentityLabels.agreementTag: Data(repeating: 0xFF, count: 7)
        ])
        let service = DeviceIdentityService(keychain: keychain)

        XCTAssertThrowsError(try service.loadOrCreate()) { error in
            XCTAssertEqual(
                error as? CryptoError,
                .identity(reason: "keychain returned malformed key bytes")
            )
        }
    }

    func testMalformedHalfStateRaisesIdentityError() throws {
        let keychain = InMemoryKeychainFake(preloaded: [
            IdentityLabels.signingTag: Data(repeating: 0xFF, count: 7)
        ])
        let service = DeviceIdentityService(keychain: keychain)

        XCTAssertThrowsError(try service.loadOrCreate()) { error in
            XCTAssertEqual(
                error as? CryptoError,
                .identity(reason: "keychain returned malformed key bytes")
            )
        }
    }

    // MARK: OSStatus propagation

    func testGetFailurePropagatesAsKeychainError() throws {
        let keychain = InMemoryKeychainFake()
        let injected = CryptoError.keychain(reason: "OSStatus: -25291")
        keychain.failNext(.get, for: IdentityLabels.signingTag, with: injected)
        let service = DeviceIdentityService(keychain: keychain)

        XCTAssertThrowsError(try service.loadOrCreate()) { error in
            XCTAssertEqual(error as? CryptoError, injected)
        }
    }
}
#endif
