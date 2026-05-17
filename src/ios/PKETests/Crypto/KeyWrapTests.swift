// Tests for the ECDH-P256 + HKDF-SHA256 + AES-256-GCM key wrap primitive
// (HLAM-28). Covers AC #1, #3, #4, #5 with random keys, the length gate and
// region-by-region tamper detection, plus the shared-vector parametric runner
// from `src/shared/test_vectors/ecdh_wrap/` (AC #2, #8).

import XCTest
import enum Crypto.AES
import enum Crypto.P256
import struct Crypto.SymmetricKey
@testable import PKECrypto

final class KeyWrapTests: XCTestCase {

    // MARK: - AC #1 — 60-byte output

    func test_wrap_returns_60_bytes() throws {
        let snapshotKey = SymmetricKey(size: .bits256)
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()
        let wrapped = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(recipient.publicKey),
            snapshotId: "snap-1"
        )
        XCTAssertEqual(wrapped.count, KeyWrap.wrappedByteCount)
        XCTAssertEqual(wrapped.count, 60)
    }

    // MARK: - AC #3 — round trip

    func test_wrap_unwrap_round_trip_recovers_snapshot_key() throws {
        let snapshotKey = SymmetricKey(size: .bits256)
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()
        let snapshotId = "snap-roundtrip"

        let wrapped = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(recipient.publicKey),
            snapshotId: snapshotId
        )
        let recovered = try KeyWrap.unwrap(
            wrapped,
            recipientPrivate: recipient,
            ownerPublic: AgreementPublicKey(owner.publicKey),
            snapshotId: snapshotId
        )
        XCTAssertEqual(rawBytes(snapshotKey), rawBytes(recovered))
    }

    // MARK: - AC #4 — wrong snapshot id

    func test_unwrap_with_wrong_snapshot_id_throws_aead() throws {
        let snapshotKey = SymmetricKey(size: .bits256)
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()

        let wrapped = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(recipient.publicKey),
            snapshotId: "snap-A"
        )
        XCTAssertThrowsError(
            try KeyWrap.unwrap(
                wrapped,
                recipientPrivate: recipient,
                ownerPublic: AgreementPublicKey(owner.publicKey),
                snapshotId: "snap-B"
            )
        ) { error in
            assertAead(error, contains: "tag verification failed")
        }
    }

    // MARK: - AC #5 — corrupted bytes

    func test_unwrap_with_corrupted_ciphertext_byte_throws_aead() throws {
        let wrapped = try makeWrapped()
        var corrupted = wrapped.bytes
        corrupted.wrapped[20] ^= 0x01  // mutate ciphertext region
        XCTAssertThrowsError(
            try KeyWrap.unwrap(
                corrupted.wrapped,
                recipientPrivate: corrupted.recipient,
                ownerPublic: AgreementPublicKey(corrupted.owner.publicKey),
                snapshotId: corrupted.snapshotId
            )
        ) { assertAead($0, contains: "tag verification failed") }
    }

    func test_unwrap_with_corrupted_tag_byte_throws_aead() throws {
        let wrapped = try makeWrapped()
        var corrupted = wrapped.bytes
        corrupted.wrapped[50] ^= 0x01  // mutate tag region
        XCTAssertThrowsError(
            try KeyWrap.unwrap(
                corrupted.wrapped,
                recipientPrivate: corrupted.recipient,
                ownerPublic: AgreementPublicKey(corrupted.owner.publicKey),
                snapshotId: corrupted.snapshotId
            )
        ) { assertAead($0, contains: "tag verification failed") }
    }

    func test_unwrap_with_corrupted_nonce_byte_throws_aead() throws {
        let wrapped = try makeWrapped()
        var corrupted = wrapped.bytes
        corrupted.wrapped[5] ^= 0x01  // mutate nonce region
        XCTAssertThrowsError(
            try KeyWrap.unwrap(
                corrupted.wrapped,
                recipientPrivate: corrupted.recipient,
                ownerPublic: AgreementPublicKey(corrupted.owner.publicKey),
                snapshotId: corrupted.snapshotId
            )
        ) { assertAead($0, contains: "tag verification failed") }
    }

    // MARK: - Edge: wrong recipient private key

    func test_unwrap_with_wrong_recipient_private_throws_aead() throws {
        let wrapped = try makeWrapped()
        let attacker = P256.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(
            try KeyWrap.unwrap(
                wrapped.bytes.wrapped,
                recipientPrivate: attacker,
                ownerPublic: AgreementPublicKey(wrapped.bytes.owner.publicKey),
                snapshotId: wrapped.bytes.snapshotId
            )
        ) { assertAead($0, contains: "tag verification failed") }
    }

    // MARK: - Edge: wrong owner public key (spoofing — STRIDE-S)

    func test_unwrap_with_wrong_owner_public_throws_aead() throws {
        let wrapped = try makeWrapped()
        let attackerOwner = P256.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(
            try KeyWrap.unwrap(
                wrapped.bytes.wrapped,
                recipientPrivate: wrapped.bytes.recipient,
                ownerPublic: AgreementPublicKey(attackerOwner.publicKey),
                snapshotId: wrapped.bytes.snapshotId
            )
        ) { assertAead($0, contains: "tag verification failed") }
    }

    // MARK: - Length gate

    func test_unwrap_rejects_non_60_byte_length_as_aead() throws {
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()
        for length in [0, 59, 61] {
            let bogus = Data(repeating: 0x00, count: length)
            XCTAssertThrowsError(
                try KeyWrap.unwrap(
                    bogus,
                    recipientPrivate: recipient,
                    ownerPublic: AgreementPublicKey(owner.publicKey),
                    snapshotId: "x"
                )
            ) { error in
                guard case .aead(let reason) = error as? CryptoError else {
                    XCTFail("expected .aead for length \(length), got \(error)")
                    return
                }
                XCTAssertTrue(
                    reason.contains("\(length)"),
                    "reason should mention length \(length), got: \(reason)"
                )
            }
        }
    }

    // MARK: - Edge: different recipient pubs → distinct wrap output

    func test_wrap_with_different_recipient_pub_produces_distinct_output() throws {
        let snapshotKey = SymmetricKey(size: .bits256)
        let owner = P256.KeyAgreement.PrivateKey()
        let r1 = P256.KeyAgreement.PrivateKey()
        let r2 = P256.KeyAgreement.PrivateKey()
        let nonce = AES.GCM.Nonce()  // pin to isolate the recipient-pub effect

        let w1 = try KeyWrap.wrapWithFixedNonce(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(r1.publicKey),
            snapshotId: "same-snap",
            nonce: nonce
        )
        let w2 = try KeyWrap.wrapWithFixedNonce(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(r2.publicKey),
            snapshotId: "same-snap",
            nonce: nonce
        )
        XCTAssertNotEqual(w1, w2)
    }

    // MARK: - Random nonce divergence

    func test_wrap_with_random_nonces_produces_distinct_outputs() throws {
        let snapshotKey = SymmetricKey(size: .bits256)
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()
        let recipientWrap = AgreementPublicKey(recipient.publicKey)
        let snapshotId = "same"
        let w1 = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: recipientWrap,
            snapshotId: snapshotId
        )
        let w2 = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: recipientWrap,
            snapshotId: snapshotId
        )
        XCTAssertNotEqual(w1, w2)
        XCTAssertNotEqual(w1.prefix(12), w2.prefix(12))
    }

    // MARK: - u16be defensive guard

    func test_u16be_rejects_oversized_length() {
        XCTAssertThrowsError(try KeyWrap.u16be(0x10000)) { error in
            guard case .wrap(let reason) = error as? CryptoError else {
                XCTFail("expected .wrap, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("u16be"), "got: \(reason)")
        }
    }

    func test_u16be_accepts_boundary_values() throws {
        XCTAssertEqual(try KeyWrap.u16be(0), Data([0x00, 0x00]))
        XCTAssertEqual(try KeyWrap.u16be(11), Data([0x00, 0x0B]))
        XCTAssertEqual(try KeyWrap.u16be(65), Data([0x00, 0x41]))
        XCTAssertEqual(try KeyWrap.u16be(0xFFFF), Data([0xFF, 0xFF]))
    }

    // MARK: - Edge: empty / unicode snapshot id

    func test_empty_snapshot_id_round_trips() throws {
        let snapshotKey = SymmetricKey(size: .bits256)
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()
        let wrapped = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(recipient.publicKey),
            snapshotId: ""
        )
        let recovered = try KeyWrap.unwrap(
            wrapped,
            recipientPrivate: recipient,
            ownerPublic: AgreementPublicKey(owner.publicKey),
            snapshotId: ""
        )
        XCTAssertEqual(rawBytes(snapshotKey), rawBytes(recovered))
    }

    func test_unicode_snapshot_id_round_trips() throws {
        let snapshotKey = SymmetricKey(size: .bits256)
        let owner = P256.KeyAgreement.PrivateKey()
        let recipient = P256.KeyAgreement.PrivateKey()
        let snapshotId = "snap-ünîcødé-🔐"
        let wrapped = try KeyWrap.wrap(
            snapshotKey: snapshotKey,
            ownerPrivate: owner,
            recipientPublic: AgreementPublicKey(recipient.publicKey),
            snapshotId: snapshotId
        )
        let recovered = try KeyWrap.unwrap(
            wrapped,
            recipientPrivate: recipient,
            ownerPublic: AgreementPublicKey(owner.publicKey),
            snapshotId: snapshotId
        )
        XCTAssertEqual(rawBytes(snapshotKey), rawBytes(recovered))
    }

    // MARK: - AC #2 + #8 — parametric vector runner against shared fixtures

    func test_ecdh_wrap_vectors_from_bundle() throws {
        let urls = loadEcdhWrapVectorURLs()
        if urls.isEmpty {
            throw XCTSkip("no ecdh_wrap fixtures present")
        }
        XCTAssertGreaterThanOrEqual(urls.count, 3, "expected p1, p2, n1 fixtures")

        for url in urls.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            let data = try Data(contentsOf: url)
            let vector = try JSONDecoder().decode(EcdhWrapVector.self, from: data)
            try runVector(vector)
        }
    }

    private func loadEcdhWrapVectorURLs(file: StaticString = #filePath) -> [URL] {
        // Resolve the source-tree path so we don't depend on SwiftPM resource
        // bundling. From this file's location:
        //   src/ios/PKETests/Crypto/KeyWrapTests.swift
        // up four levels lands at the repo root, then descend into
        // `src/shared/test_vectors/ecdh_wrap/`. The symlink at
        // `PKETests/Crypto/Resources/test_vectors` is preserved for
        // discoverability and tooling but is not relied on for lookup.
        let dir = URL(fileURLWithPath: "\(file)")
            .deletingLastPathComponent()   // PKETests/Crypto
            .deletingLastPathComponent()   // PKETests
            .deletingLastPathComponent()   // ios
            .deletingLastPathComponent()   // src
            .appendingPathComponent("shared/test_vectors/ecdh_wrap", isDirectory: true)
        guard let contents = try? FileManager.default.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil
        ) else {
            return []
        }
        return contents.filter { $0.pathExtension == "json" }
    }

    // Shared helpers (`makeWrapped`, `rawBytes`, `assertAead`, fixture structs)
    // live in `KeyWrapVectorRunner.swift` to keep this class under SwiftLint's
    // type-body-length threshold.
}
