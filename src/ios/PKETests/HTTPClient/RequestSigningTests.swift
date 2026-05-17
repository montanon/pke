// HLAM-147 — canonical-encoding integration tests.
//
// Exercises the four ACs:
//   * #1 `canonicalBytes` routes through `Encodable.toJSONValue` →
//     `CanonicalJSON.encode` and matches the bytes a direct call to the
//     same pipeline would produce.
//   * #2 `makeJSONRequest` stamps the canonical `Content-Type` header.
//   * #3 No parallel encoder exists under `Networking/` (covered by a
//     repository-level grep guard in this file).
//   * #4 Round-trip: a fixture model with sortable keys + nested values
//     round-trips to expected canonical bytes (no key reordering or
//     whitespace surprises).

#if canImport(Security)
import Foundation
import XCTest
import enum Crypto.P256
import PKECrypto
import PKEIdentity
import PKEProtocol
@testable import PKEHTTPClient

final class RequestSigningTests: XCTestCase {

    // MARK: AC #1 — pipeline parity with direct CanonicalJSON.encode

    func testCanonicalBytesMatchesDirectPipeline() throws {
        let model = SampleBody(zeta: 1, alpha: "two")

        let viaBuilder = try RequestSigning.canonicalBytes(model)
        let direct = try CanonicalJSON.encode(model.toJSONValue())

        XCTAssertEqual(viaBuilder, direct)
    }

    // MARK: AC #4 — fixture matches the canonical-encoding spec

    func testCanonicalBytesProduceSortedMinifiedOutput() throws {
        let model = SampleBody(zeta: 1, alpha: "two")
        let bytes = try RequestSigning.canonicalBytes(model)

        // Keys sorted by UTF-8 byte order (a < z), minified separators,
        // double-quoted strings, no trailing newline — per
        // context/16_canonical_encoding.md §Canonical JSON.
        XCTAssertEqual(String(data: bytes, encoding: .utf8), "{\"alpha\":\"two\",\"zeta\":1}")
    }

    // MARK: AC #2 — Content-Type + body wired correctly

    func testMakeJSONRequestSetsCanonicalContentTypeAndBody() throws {
        // swiftlint:disable:next force_unwrapping
        let url = URL(string: "https://pke.test.invalid/v1/snapshots")!
        let model = SampleBody(zeta: 1, alpha: "two")

        let request = try RequestSigning.makeJSONRequest(
            url: url,
            method: "POST",
            body: model
        )

        XCTAssertEqual(request.url, url)
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(
            request.value(forHTTPHeaderField: "Content-Type"),
            "application/json; charset=utf-8"
        )
        XCTAssertEqual(request.httpBody, try RequestSigning.canonicalBytes(model))
    }

    // MARK: AC #2 — the content-type constant itself is the pinned value

    func testCanonicalJSONContentTypeIsPinned() {
        XCTAssertEqual(
            RequestSigning.canonicalJSONContentType,
            "application/json; charset=utf-8"
        )
    }

    // MARK: AC #3 — repository-level guard against a parallel encoder

    func testNoParallelCanonicalEncoderUnderNetworking() throws {
        // Walks the Networking source tree and asserts the only canonical-
        // JSON call sites here are integrations (`CanonicalJSON.encode(`),
        // never definitions. A `public func encode(` directly inside
        // Networking would mean someone reintroduced a parallel encoder.
        let networkingRoot = try networkingRootURL()
        let manager = FileManager.default
        guard let enumerator = manager.enumerator(
            at: networkingRoot,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            XCTFail("could not enumerate \(networkingRoot.path)")
            return
        }

        var offenders: [String] = []
        for case let url as URL in enumerator where url.pathExtension == "swift" {
            let source = try String(contentsOf: url, encoding: .utf8)
            // Matches a public top-level function literally named `encode`
            // taking a JSONValue — the shape of an encoder definition.
            // The integration call sites read `CanonicalJSON.encode(` and
            // do not match this prefix.
            if source.contains("public static func encode(_ value: JSONValue)") ||
                source.contains("public func encode(_ value: JSONValue)") {
                offenders.append(url.path)
            }
        }

        XCTAssertTrue(
            offenders.isEmpty,
            "parallel canonical-JSON encoder definitions found under Networking/: \(offenders)"
        )
    }

    // MARK: HLAM-148 AC #1 / #4 — sign + verify round-trip

    func testSignProducesSignatureThatVerifiesOverStrippedCanonicalBytes() throws {
        let identity = makeIdentity()
        let payload = FixturePayload(snapshotId: "snap-001", nonceHex: "abcd")

        let signedBytes = try RequestSigning.sign(payload, with: identity)
        let (signature, strippedBytes) = try extractSignatureAndStrippedBytes(
            from: signedBytes,
            signatureKey: FixturePayload.signatureFieldKey
        )

        // AC #2 — raw P1363 = exactly 64 bytes.
        XCTAssertEqual(signature.count, 64)
        // AC #4 — round-trip with HLAM-7 verify against the same key pair.
        try Signatures.verify(
            signature,
            of: strippedBytes,
            by: identity.signingKey.publicKey
        )
    }

    // MARK: HLAM-148 AC #3 — bytes signed over payload minus signature field

    func testSignStripsExistingSignatureFieldBeforeHashing() throws {
        let identity = makeIdentity()
        let bogus = String(repeating: "A", count: 86) // ≈ 64 bytes b64url
        let payload = FixturePayload(
            snapshotId: "snap-001",
            nonceHex: "abcd",
            existingSignature: bogus
        )

        let signedBytes = try RequestSigning.sign(payload, with: identity)
        let (signature, strippedBytes) = try extractSignatureAndStrippedBytes(
            from: signedBytes,
            signatureKey: FixturePayload.signatureFieldKey
        )

        // Verifies against payload-minus-signature bytes — the bogus value
        // was excluded from the hash input.
        try Signatures.verify(signature, of: strippedBytes, by: identity.signingKey.publicKey)

        // And does not verify against bytes that still include the bogus
        // signature — proof the signing input excluded it.
        let bytesWithBogus = try CanonicalJSON.encode(payload.toJSONValue())
        XCTAssertThrowsError(
            try Signatures.verify(
                signature,
                of: bytesWithBogus,
                by: identity.signingKey.publicKey
            )
        )
    }

    // MARK: HLAM-148 AC #1 — protocol payload type conformances

    func testProtocolPayloadsConformWithCorrectSignatureFieldKeys() {
        XCTAssertEqual(SnapshotCommitment.signatureFieldKey, "owner_signature")
        XCTAssertEqual(WitnessAttestation.signatureFieldKey, "witness_signature")
        XCTAssertEqual(KeyGrant.signatureFieldKey, "grant_signature")
    }

    // MARK: HLAM-148 AC #1 — end-to-end with a real protocol payload

    func testSnapshotCommitmentSignVerifyRoundTrip() throws {
        let identity = makeIdentity()
        let commitment = makeSnapshotCommitment()

        let signedBytes = try RequestSigning.sign(commitment, with: identity)
        let (signature, strippedBytes) = try extractSignatureAndStrippedBytes(
            from: signedBytes,
            signatureKey: SnapshotCommitment.signatureFieldKey
        )

        XCTAssertEqual(signature.count, 64)
        try Signatures.verify(signature, of: strippedBytes, by: identity.signingKey.publicKey)
    }

    // MARK: - Helpers

    private func makeIdentity() -> DeviceIdentity {
        DeviceIdentity(
            signingKey: P256.Signing.PrivateKey(),
            agreementKey: P256.KeyAgreement.PrivateKey()
        )
    }

    private func makeSnapshotCommitment(
        ownerSignature: Data = Data()
    ) -> SnapshotCommitment {
        SnapshotCommitment(
            version: "0.1",
            snapshotId: "snap-test-001",
            ciphertextHash: Data(repeating: 0xAB, count: 32),
            ownerSigningPublicKey: Data(repeating: 0xCD, count: 33),
            ownerEncryptionPublicKey: Data(repeating: 0xEF, count: 33),
            captureTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 0)),
            metadataPolicy: SnapshotCommitment.MetadataPolicy(
                locationPublic: true,
                locationPrecision: nil,
                mediaType: "image/jpeg"
            ),
            sessionNonce: Data(repeating: 0x01, count: 16),
            ownerSignature: ownerSignature
        )
    }

    /// Decodes `signedBytes` back into a JSON object, pulls out the
    /// base64url-encoded signature stored under `signatureKey`, and
    /// returns it alongside the canonical bytes of the same object
    /// **with the signature entry stripped**. These are the two halves
    /// that `Signatures.verify` consumes.
    private func extractSignatureAndStrippedBytes(
        from signedBytes: Data,
        signatureKey: String
    ) throws -> (signature: Data, stripped: Data) {
        let parsed = try JSONValue.decode(signedBytes)
        guard case .object(let pairs) = parsed else {
            throw TestFailure.notAnObject
        }
        let signatureEntry = pairs.first { $0.0 == signatureKey }
        guard case .string(let signatureString)? = signatureEntry?.1 else {
            throw TestFailure.missingSignature
        }
        let signature = try Base64URL.decode(signatureString)
        let strippedPairs = pairs.filter { $0.0 != signatureKey }
        let stripped = try CanonicalJSON.encode(.object(strippedPairs))
        return (signature, stripped)
    }

    private enum TestFailure: Error {
        case notAnObject
        case missingSignature
    }

    /// Walks up from this test file to `src/ios/PKE/Networking`. The path is
    /// derived from `#filePath` so it works regardless of where the test
    /// bundle is staged (CI cache directory, Xcode DerivedData, etc.).
    private func networkingRootURL() throws -> URL {
        let here = URL(fileURLWithPath: #filePath)
        // here = .../src/ios/PKETests/HTTPClient/RequestSigningTests.swift
        // PKE/Networking lives at .../src/ios/PKE/Networking
        let iosRoot = here
            .deletingLastPathComponent() // HTTPClient
            .deletingLastPathComponent() // PKETests
            .deletingLastPathComponent() // ios
        return iosRoot
            .appendingPathComponent("PKE", isDirectory: true)
            .appendingPathComponent("Networking", isDirectory: true)
    }
}

// MARK: - Fixtures

/// Two-field `Encodable` whose declared order (`zeta` before `alpha`)
/// differs from the canonical order, so any failure to sort keys surfaces
/// immediately.
private struct SampleBody: Encodable {
    let zeta: Int
    let alpha: String
}

/// Minimal `SignablePayload` used to exercise `RequestSigning.sign` without
/// the surrounding ceremony of constructing a full protocol payload. Carries
/// an optional pre-existing signature so the strip-before-hash behaviour can
/// be tested directly.
private struct FixturePayload: SignablePayload {
    static let signatureFieldKey = "fixture_signature"

    let snapshotId: String
    let nonceHex: String
    let existingSignature: String?

    init(snapshotId: String, nonceHex: String, existingSignature: String? = nil) {
        self.snapshotId = snapshotId
        self.nonceHex = nonceHex
        self.existingSignature = existingSignature
    }

    enum CodingKeys: String, CodingKey {
        case snapshotId = "snapshot_id"
        case nonceHex = "nonce_hex"
        case fixtureSignature = "fixture_signature"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(snapshotId, forKey: .snapshotId)
        try container.encode(nonceHex, forKey: .nonceHex)
        try container.encodeIfPresent(existingSignature, forKey: .fixtureSignature)
    }
}
#endif
