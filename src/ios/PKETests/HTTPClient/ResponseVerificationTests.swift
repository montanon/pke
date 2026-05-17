// HLAM-149 — response-verification pipeline tests.
//
// Builds known-good signed payloads with `RequestSigning.sign` (HLAM-148)
// — that way the wire encoding under test is exactly the one the iOS
// client emits — then re-decodes them and runs `ResponseVerification.verify`
// over the result. The good cases must pass; tampered cases must throw
// `PKENetworkError.verificationFailed(.signatureVerification)`.

#if canImport(Security)
import Foundation
import XCTest
import enum Crypto.P256
import PKECrypto
import PKEIdentity
import PKEProtocol
@testable import PKEHTTPClient

final class ResponseVerificationTests: XCTestCase {

    // MARK: AC #1 / #4 — known-good single payload verifies

    func testVerifyAcceptsKnownGoodSnapshotCommitment() throws {
        let identity = makeIdentity()
        let signed = try makeSignedSnapshotCommitment(identity: identity)
        try ResponseVerification.verify(signed)
    }

    func testVerifyAcceptsKnownGoodWitnessAttestation() throws {
        let identity = makeIdentity()
        let signed = try makeSignedWitnessAttestation(identity: identity)
        try ResponseVerification.verify(signed)
    }

    func testVerifyAcceptsKnownGoodKeyGrant() throws {
        let identity = makeIdentity()
        let signed = try makeSignedKeyGrant(identity: identity)
        try ResponseVerification.verify(signed)
    }

    // MARK: AC #1 / #4 — known-good bundle (mixed payload types) verifies

    func testVerifyAllAcceptsKnownGoodBundle() throws {
        let owner = makeIdentity()
        let witness = makeIdentity()
        let granter = makeIdentity()
        let bundle: [any SignablePayload] = [
            try makeSignedSnapshotCommitment(identity: owner),
            try makeSignedWitnessAttestation(identity: witness),
            try makeSignedKeyGrant(identity: granter)
        ]
        try ResponseVerification.verifyAll(bundle)
    }

    // MARK: AC #2 / #4 — tampered payload fails with verificationFailed

    func testVerifyRejectsTamperedSnapshotId() throws {
        let identity = makeIdentity()
        let signed = try makeSignedSnapshotCommitment(identity: identity, snapshotId: "snap-001")
        // Re-issue the SnapshotCommitment with a different snapshot id but
        // the **same** signature and public key — i.e. simulate an attacker
        // tampering with one byte of the body in transit.
        let tampered = SnapshotCommitment(
            version: signed.version,
            snapshotId: "snap-XXX",
            ciphertextHash: signed.ciphertextHash,
            ownerSigningPublicKey: signed.ownerSigningPublicKey,
            ownerEncryptionPublicKey: signed.ownerEncryptionPublicKey,
            captureTimestamp: signed.captureTimestamp,
            metadataPolicy: signed.metadataPolicy,
            sessionNonce: signed.sessionNonce,
            ownerSignature: signed.ownerSignature
        )

        XCTAssertThrowsError(try ResponseVerification.verify(tampered)) { error in
            guard case PKENetworkError.verificationFailed(let cryptoError) = error else {
                XCTFail("expected PKENetworkError.verificationFailed, got \(error)")
                return
            }
            XCTAssertEqual(cryptoError, .signatureVerification)
        }
    }

    func testVerifyAllRejectsBundleWithOneTamperedAttestation() throws {
        let owner = makeIdentity()
        let witness = makeIdentity()
        let granter = makeIdentity()

        let goodCommitment = try makeSignedSnapshotCommitment(identity: owner)
        let goodAttestation = try makeSignedWitnessAttestation(identity: witness)
        let goodGrant = try makeSignedKeyGrant(identity: granter)

        // Tamper only the attestation: flip a byte in the snapshotId so the
        // signature no longer covers the current canonical bytes.
        let tamperedAttestation = WitnessAttestation(
            version: goodAttestation.version,
            snapshotId: goodAttestation.snapshotId + "X",
            ciphertextHash: goodAttestation.ciphertextHash,
            sessionNonce: goodAttestation.sessionNonce,
            ownerSigningPublicKey: goodAttestation.ownerSigningPublicKey,
            witnessSigningPublicKey: goodAttestation.witnessSigningPublicKey,
            witnessTimestamp: goodAttestation.witnessTimestamp,
            transport: goodAttestation.transport,
            proximityClaim: goodAttestation.proximityClaim,
            witnessSignature: goodAttestation.witnessSignature
        )

        let bundle: [any SignablePayload] = [goodCommitment, tamperedAttestation, goodGrant]
        XCTAssertThrowsError(try ResponseVerification.verifyAll(bundle)) { error in
            guard case PKENetworkError.verificationFailed(let cryptoError) = error else {
                XCTFail("expected PKENetworkError.verificationFailed, got \(error)")
                return
            }
            XCTAssertEqual(cryptoError, .signatureVerification)
        }
    }

    // MARK: AC #2 — malformed inline public key surfaces verificationFailed

    func testVerifyRejectsCommitmentWithCorruptedInlinePublicKey() throws {
        let identity = makeIdentity()
        let good = try makeSignedSnapshotCommitment(identity: identity)
        let mangled = SnapshotCommitment(
            version: good.version,
            snapshotId: good.snapshotId,
            ciphertextHash: good.ciphertextHash,
            ownerSigningPublicKey: Data(repeating: 0xFF, count: 64),
            ownerEncryptionPublicKey: good.ownerEncryptionPublicKey,
            captureTimestamp: good.captureTimestamp,
            metadataPolicy: good.metadataPolicy,
            sessionNonce: good.sessionNonce,
            ownerSignature: good.ownerSignature
        )

        XCTAssertThrowsError(try ResponseVerification.verify(mangled)) { error in
            guard case PKENetworkError.verificationFailed = error else {
                XCTFail("expected PKENetworkError.verificationFailed, got \(error)")
                return
            }
        }
    }

    // AC #3 — envelope is unsigned, never trusted. `ResponseVerification`
    // exposes only inner-payload entry points (`verify(_:)` and
    // `verifyAll(_:)`). No envelope-level signature check exists; the
    // contract is pinned by the file header comment and reinforced here:
    // no test in this suite even spells out an envelope-shaped value,
    // because there is no envelope-level surface to exercise.

    // MARK: - Helpers

    private func makeIdentity() -> DeviceIdentity {
        DeviceIdentity(
            signingKey: P256.Signing.PrivateKey(),
            agreementKey: P256.KeyAgreement.PrivateKey()
        )
    }

    private func makeSignedSnapshotCommitment(
        identity: DeviceIdentity,
        snapshotId: String = "snap-001"
    ) throws -> SnapshotCommitment {
        let unsigned = SnapshotCommitment(
            version: "0.1",
            snapshotId: snapshotId,
            ciphertextHash: Data(repeating: 0xAB, count: 32),
            ownerSigningPublicKey: identity.signingKey.publicKey.rawRepresentation,
            ownerEncryptionPublicKey: identity.agreementKey.publicKey.rawRepresentation,
            captureTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 1_700_000_000)),
            metadataPolicy: SnapshotCommitment.MetadataPolicy(
                locationPublic: true,
                locationPrecision: nil,
                mediaType: "image/jpeg"
            ),
            sessionNonce: Data(repeating: 0x01, count: 16),
            ownerSignature: Data()
        )
        let signedBytes = try RequestSigning.sign(unsigned, with: identity)
        return try JSONDecoder().decode(SnapshotCommitment.self, from: signedBytes)
    }

    private func makeSignedWitnessAttestation(
        identity: DeviceIdentity
    ) throws -> WitnessAttestation {
        let unsigned = WitnessAttestation(
            version: "0.1",
            snapshotId: "snap-001",
            ciphertextHash: Data(repeating: 0xAB, count: 32),
            sessionNonce: Data(repeating: 0x01, count: 16),
            ownerSigningPublicKey: Data(repeating: 0xCD, count: 64),
            witnessSigningPublicKey: identity.signingKey.publicKey.rawRepresentation,
            witnessTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 1_700_000_500)),
            transport: "bluetooth",
            proximityClaim: WitnessAttestation.ProximityClaim(
                method: "rssi",
                exactLocationPublic: false
            ),
            witnessSignature: Data()
        )
        let signedBytes = try RequestSigning.sign(unsigned, with: identity)
        return try JSONDecoder().decode(WitnessAttestation.self, from: signedBytes)
    }

    private func makeSignedKeyGrant(
        identity: DeviceIdentity
    ) throws -> KeyGrant {
        let unsigned = KeyGrant(
            version: "0.1",
            grantId: "grant-001",
            snapshotId: "snap-001",
            recipientEncryptionPublicKey: Data(repeating: 0xEF, count: 64),
            wrappedSnapshotKey: Data(repeating: 0x42, count: 48),
            wrappingAlgorithm: "AES-256-GCM",
            grantedBySigningPublicKey: identity.signingKey.publicKey.rawRepresentation,
            grantTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 1_700_001_000)),
            grantSignature: Data()
        )
        let signedBytes = try RequestSigning.sign(unsigned, with: identity)
        return try JSONDecoder().decode(KeyGrant.self, from: signedBytes)
    }
}
#endif
