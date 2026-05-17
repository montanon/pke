#if canImport(Security)
import Foundation
import PKECrypto
import Security
import XCTest
import enum Crypto.P256
@testable import PKEIdentity

final class PKEIdentityTests: XCTestCase {

    private let testLabel = "com.pke.identity.test.\(UUID().uuidString)"
    private let keychain = Keychain()

    override func tearDown() {
        try? keychain.delete(label: testLabel)
        super.tearDown()
    }

    // MARK: - IdentityLabels

    func testIdentityLabelsArePinned() {
        XCTAssertEqual(IdentityLabels.signingTag, "com.pke.identity.signing")
        XCTAssertEqual(IdentityLabels.agreementTag, "com.pke.identity.agreement")
    }

    // MARK: - Keychain

    func testKeychainRoundTrip() throws {
        try skipWithoutKeychainEntitlement()
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04])
        try keychain.set(label: testLabel, data: payload)
        let fetched = try keychain.get(label: testLabel)
        XCTAssertEqual(fetched, payload)
    }

    func testKeychainGetReturnsNilWhenAbsent() throws {
        let fetched = try keychain.get(label: testLabel)
        XCTAssertNil(fetched)
    }

    func testKeychainDuplicateAddFails() throws {
        try skipWithoutKeychainEntitlement()
        let payload = Data([0x10, 0x20, 0x30])
        try keychain.set(label: testLabel, data: payload)
        XCTAssertThrowsError(try keychain.set(label: testLabel, data: payload)) { error in
            switch error as? CryptoError {
            case .keychain(let reason):
                XCTAssertTrue(reason.contains("\(errSecDuplicateItem)"), "reason was: \(reason)")
            default:
                XCTFail("expected CryptoError.keychain, got \(error)")
            }
        }
    }

    func testKeychainDeleteIsIdempotent() throws {
        try skipWithoutKeychainEntitlement()
        XCTAssertNoThrow(try keychain.delete(label: testLabel))
        try keychain.set(label: testLabel, data: Data([0x01]))
        XCTAssertNoThrow(try keychain.delete(label: testLabel))
        XCTAssertNil(try keychain.get(label: testLabel))
    }

    // MARK: - PublicKeyEncoding

    func testSigningPublicKeyEncodesRawRepresentation() throws {
        let key = P256.Signing.PrivateKey().publicKey
        let encoded = PublicKeyEncoding.signingPublicKey(key)
        let decoded = try PKECrypto.Base64URL.decode(encoded)
        XCTAssertEqual(decoded, key.rawRepresentation)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
    }

    func testEncryptionPublicKeyEncodesRawRepresentation() throws {
        let key = P256.KeyAgreement.PrivateKey().publicKey
        let encoded = PublicKeyEncoding.encryptionPublicKey(key)
        let decoded = try PKECrypto.Base64URL.decode(encoded)
        XCTAssertEqual(decoded, key.rawRepresentation)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
    }

    // MARK: - helpers

    // Probe with a benign SecItemAdd against a one-shot label. If the host
    // process lacks data-protection-keychain entitlements (-34018), skip the
    // calling test — `swift test` on a bare macOS host is unentitled, while
    // real CI hosts and on-device runs are.
    private func skipWithoutKeychainEntitlement() throws {
        let probeLabel = "com.pke.identity.probe.\(UUID().uuidString)"
        let probe = Keychain()
        do {
            try probe.set(label: probeLabel, data: Data([0x00]))
            try? probe.delete(label: probeLabel)
        } catch let CryptoError.keychain(reason) where reason.contains("-34018") {
            throw XCTSkip("keychain entitlement unavailable in this host process")
        }
    }
}
#endif
