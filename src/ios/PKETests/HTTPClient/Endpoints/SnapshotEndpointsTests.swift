// HLAM-151 — Snapshot endpoint + blob upload/download tests.
//
// Drives the four `PKEHTTPClient` extension methods through the same
// `MockURLProtocol` injection pattern as `PKEHTTPClientTests.swift`. Each
// test pins one concrete acceptance criterion:
//
//   * `testCommitSnapshotSignsBodyAndPostsAndParsesHandle` — wire
//     contract: POST + canonical JSON + signed body + parsed handle.
//   * `testCommitSnapshotMapsDuplicateError` — backend envelope mapping
//     for the `duplicate` code via `PKENetworkError.from(backendError:)`.
//   * `testUploadBlobSendsOctetStreamPut` — PUT + octet-stream + body
//     equality + `/blob` suffix.
//   * `testUploadBlobMapsHashMismatchError` — 422 + `hash_mismatch`
//     envelope → `.hashMismatch`.
//   * `testFetchSnapshotBundleVerifiesAllInnerPayloads` — happy path,
//     `ResponseVerification` accepts every inner payload signed under a
//     fresh `RequestSigning.sign` call.
//   * `testFetchSnapshotBundleRejectsTamperedAttestation` — tamper one
//     byte of one attestation; expect the verification layer to surface
//     `.verificationFailed(.signatureVerification)`.
//   * `testFetchBlobStreamsChunksWithoutBufferingFullPayload` — exercise
//     the `AsyncThrowingStream` end-to-end against the mock. The "never
//     buffers full payload" AC is enforced architecturally by routing
//     through `URLSession.bytes(for:)` rather than `URLSession.data(for:)`;
//     a full memory-profile assertion is not tractable in unit tests, so
//     this test confirms the bytes the mock produces round-trip through
//     the stream.
//
// Integration tests against `make serve` are deferred to HLAM-47.

#if canImport(Security)
import Foundation
import XCTest
import enum Crypto.P256
import PKECrypto
import PKEIdentity
import PKEProtocol
@testable import PKEHTTPClient

final class SnapshotEndpointsTests: XCTestCase {

    override func tearDown() {
        MockURLProtocol.handler = nil
        super.tearDown()
    }

    // MARK: - commitSnapshot

    func testCommitSnapshotSignsBodyAndPostsAndParsesHandle() async throws {
        let baseURL = makeBaseURL()
        let identity = makeIdentity()
        let commitment = makeUnsignedCommitment(identity: identity)

        let expectedHandle = SnapshotHandle(
            snapshotId: "snap-abc",
            // swiftlint:disable:next force_unwrapping
            blobUploadURL: URL(string: "https://uploads.test.invalid/blob/abc")!
        )
        let responseBody = try encodeJSON(expectedHandle)

        var capturedRequest: URLRequest?
        var capturedBody: Data?
        MockURLProtocol.handler = { request in
            capturedRequest = request
            capturedBody = MockURLProtocol.bodyFromRequest(request)
            let response = HTTPURLResponse(
                url: baseURL.appendingPathComponent("v1/snapshots"),
                statusCode: 201,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json; charset=utf-8"]
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, responseBody)
        }

        let client = makeMockClient(baseURL: baseURL, identity: identity)
        let handle = try await client.commitSnapshot(commitment)

        XCTAssertEqual(handle, expectedHandle)

        let request = try XCTUnwrap(capturedRequest)
        XCTAssertEqual(request.url?.absoluteString.hasSuffix("/v1/snapshots"), true)
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(
            request.value(forHTTPHeaderField: "Content-Type"),
            "application/json; charset=utf-8"
        )

        // Body parses back to JSON containing an `owner_signature` field
        // whose value is a base64url string of length 86-88 (P1363 64
        // bytes encode to 86 chars without padding; allow ±2 for sane
        // alternate encodings).
        let bodyData = try XCTUnwrap(capturedBody)
        let parsed = try JSONSerialization.jsonObject(with: bodyData) as? [String: Any]
        let body = try XCTUnwrap(parsed)
        let signatureString = try XCTUnwrap(body["owner_signature"] as? String)
        XCTAssertGreaterThanOrEqual(signatureString.count, 80)
        XCTAssertLessThanOrEqual(signatureString.count, 96)
        // Verify it decodes as base64url (no '+' or '/' or '=' padding).
        XCTAssertFalse(signatureString.contains("+"))
        XCTAssertFalse(signatureString.contains("/"))
        XCTAssertFalse(signatureString.contains("="))
    }

    func testCommitSnapshotMapsDuplicateError() async throws {
        let baseURL = makeBaseURL()
        let identity = makeIdentity()
        let commitment = makeUnsignedCommitment(identity: identity)

        MockURLProtocol.handler = { _ in
            let body = Data("""
            {"error":{"code":"duplicate","detail":"snap-abc already committed"}}
            """.utf8)
            let response = HTTPURLResponse(
                url: baseURL.appendingPathComponent("v1/snapshots"),
                statusCode: 409,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, body)
        }

        let client = makeMockClient(baseURL: baseURL, identity: identity)
        do {
            _ = try await client.commitSnapshot(commitment)
            XCTFail("expected PKENetworkError.duplicate")
        } catch let error as PKENetworkError {
            XCTAssertEqual(error, .duplicate(detail: "snap-abc already committed"))
        }
    }

    // MARK: - uploadBlob

    func testUploadBlobSendsOctetStreamPut() async throws {
        let baseURL = makeBaseURL()
        let identity = makeIdentity()
        let ciphertext = Data((0..<64).map { UInt8($0) })

        var capturedRequest: URLRequest?
        var capturedBody: Data?
        MockURLProtocol.handler = { request in
            capturedRequest = request
            capturedBody = MockURLProtocol.bodyFromRequest(request)
            // swiftlint:disable:next force_unwrapping
            let url = request.url!
            let response = HTTPURLResponse(
                url: url,
                statusCode: 204,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, Data())
        }

        let client = makeMockClient(baseURL: baseURL, identity: identity)
        try await client.uploadBlob("snap-abc", ciphertext: ciphertext)

        let request = try XCTUnwrap(capturedRequest)
        XCTAssertEqual(request.httpMethod, "PUT")
        XCTAssertEqual(
            request.value(forHTTPHeaderField: "Content-Type"),
            "application/octet-stream"
        )
        XCTAssertEqual(
            request.url?.absoluteString.hasSuffix("/v1/snapshots/snap-abc/blob"),
            true
        )
        XCTAssertEqual(capturedBody, ciphertext)
    }

    func testUploadBlobMapsHashMismatchError() async throws {
        let baseURL = makeBaseURL()
        let identity = makeIdentity()

        MockURLProtocol.handler = { request in
            // swiftlint:disable:next force_unwrapping
            let url = request.url!
            let body = Data("""
            {"error":{"code":"hash_mismatch","detail":"sha256 disagreement"}}
            """.utf8)
            let response = HTTPURLResponse(
                url: url,
                statusCode: 422,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, body)
        }

        let client = makeMockClient(baseURL: baseURL, identity: identity)
        do {
            try await client.uploadBlob("snap-abc", ciphertext: Data([0x01, 0x02]))
            XCTFail("expected PKENetworkError.hashMismatch")
        } catch let error as PKENetworkError {
            XCTAssertEqual(error, .hashMismatch)
        }
    }

    // MARK: - fetchSnapshotBundle

    func testFetchSnapshotBundleVerifiesAllInnerPayloads() async throws {
        let baseURL = makeBaseURL()
        let owner = makeIdentity()
        let witness = makeIdentity()
        let granter = makeIdentity()

        let commitment = try makeSignedCommitment(identity: owner)
        let attestation = try makeSignedAttestation(identity: witness)
        let keyGrant = try makeSignedKeyGrant(identity: granter)
        let bundle = SnapshotBundle(
            commitment: commitment,
            attestations: [attestation],
            keyGrants: [keyGrant]
        )
        let bundleBytes = try encodeJSON(bundle)

        MockURLProtocol.handler = { request in
            // swiftlint:disable:next force_unwrapping
            let url = request.url!
            let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json; charset=utf-8"]
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, bundleBytes)
        }

        let client = makeMockClient(baseURL: baseURL, identity: owner)
        let observed = try await client.fetchSnapshotBundle("snap-001")
        XCTAssertEqual(observed, bundle)
    }

    func testFetchSnapshotBundleRejectsTamperedAttestation() async throws {
        let baseURL = makeBaseURL()
        let owner = makeIdentity()
        let commitment = try makeSignedCommitment(identity: owner)
        let attestation = try makeSignedAttestation(identity: makeIdentity())
        let keyGrant = try makeSignedKeyGrant(identity: makeIdentity())
        let bundle = SnapshotBundle(
            commitment: commitment,
            attestations: [Self.tamperedSnapshotId(of: attestation)],
            keyGrants: [keyGrant]
        )
        let bundleBytes = try encodeJSON(bundle)

        MockURLProtocol.handler = Self.bundle200Handler(bundleBytes)

        let client = makeMockClient(baseURL: baseURL, identity: owner)
        do {
            _ = try await client.fetchSnapshotBundle("snap-001")
            XCTFail("expected PKENetworkError.verificationFailed")
        } catch let error as PKENetworkError {
            guard case .verificationFailed(let cryptoError) = error else {
                XCTFail("expected .verificationFailed, got \(error)")
                return
            }
            XCTAssertEqual(cryptoError, .signatureVerification)
        }
    }

    // MARK: - fetchBlob

    func testFetchBlobStreamsChunksWithoutBufferingFullPayload() async throws {
        let baseURL = makeBaseURL()
        let identity = makeIdentity()
        let payload = Data((0..<256).map { UInt8($0 & 0xFF) })

        MockURLProtocol.handler = { request in
            // swiftlint:disable:next force_unwrapping
            let url = request.url!
            let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/octet-stream"]
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, payload)
        }

        let client = makeMockClient(baseURL: baseURL, identity: identity)
        let stream = client.fetchBlob("snap-abc")

        var collected = Data()
        for try await chunk in stream {
            collected.append(chunk)
        }
        XCTAssertEqual(collected, payload)
        // Architectural enforcement of AC #4 (never buffer the full
        // payload) lives in the production path: `fetchBlob` routes
        // through `URLSession.bytes(for:)` rather than
        // `URLSession.data(for:)`. A memory-profile assertion is not
        // tractable here; this test confirms byte-level round-trip.
    }

}

// MARK: - Helpers (file-scope to keep the test class body under SwiftLint's
// `type_body_length` ceiling). All members stay `fileprivate` so they remain
// scoped to this test file and never leak into the rest of the module.

fileprivate extension SnapshotEndpointsTests {

    /// Returns a `WitnessAttestation` whose `snapshotId` has had one
    /// character appended — the inline signature no longer covers the
    /// current canonical bytes, so re-verification must fail.
    static func tamperedSnapshotId(of attestation: WitnessAttestation) -> WitnessAttestation {
        WitnessAttestation(
            version: attestation.version,
            snapshotId: attestation.snapshotId + "X",
            ciphertextHash: attestation.ciphertextHash,
            sessionNonce: attestation.sessionNonce,
            ownerSigningPublicKey: attestation.ownerSigningPublicKey,
            witnessSigningPublicKey: attestation.witnessSigningPublicKey,
            witnessTimestamp: attestation.witnessTimestamp,
            transport: attestation.transport,
            proximityClaim: attestation.proximityClaim,
            witnessSignature: attestation.witnessSignature
        )
    }

    /// Stock `200 OK` handler that returns the supplied bundle bytes for
    /// whichever URL is being fetched. Extracted to keep test bodies under
    /// SwiftLint's `function_body_length` ceiling.
    static func bundle200Handler(_ bytes: Data) -> (URLRequest) -> (HTTPURLResponse, Data) {
        { request in
            // swiftlint:disable:next force_unwrapping
            let url = request.url!
            let optionalResponse = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )
            // swiftlint:disable:next force_unwrapping
            let response = optionalResponse!
            return (response, bytes)
        }
    }

    func makeBaseURL() -> URL {
        // swiftlint:disable:next force_unwrapping
        URL(string: "https://pke.test.invalid")!
    }

    func makeIdentity() -> DeviceIdentity {
        DeviceIdentity(
            signingKey: P256.Signing.PrivateKey(),
            agreementKey: P256.KeyAgreement.PrivateKey()
        )
    }

    func makeMockClient(baseURL: URL, identity: DeviceIdentity) -> PKEHTTPClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        return PKEHTTPClient(
            baseURL: baseURL,
            identity: identity,
            configuration: configuration
        )
    }

    func encodeJSON<T: Encodable>(_ value: T) throws -> Data {
        try JSONEncoder().encode(value)
    }

    func makeUnsignedCommitment(identity: DeviceIdentity) -> SnapshotCommitment {
        SnapshotCommitment(
            version: "0.1",
            snapshotId: "snap-abc",
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
    }

    func makeSignedCommitment(identity: DeviceIdentity) throws -> SnapshotCommitment {
        let unsigned = makeUnsignedCommitment(identity: identity)
        let bytes = try RequestSigning.sign(unsigned, with: identity)
        return try JSONDecoder().decode(SnapshotCommitment.self, from: bytes)
    }

    func makeSignedAttestation(identity: DeviceIdentity) throws -> WitnessAttestation {
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
        let bytes = try RequestSigning.sign(unsigned, with: identity)
        return try JSONDecoder().decode(WitnessAttestation.self, from: bytes)
    }

    func makeSignedKeyGrant(identity: DeviceIdentity) throws -> KeyGrant {
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
        let bytes = try RequestSigning.sign(unsigned, with: identity)
        return try JSONDecoder().decode(KeyGrant.self, from: bytes)
    }
}

// MARK: - URLProtocol mock

/// `URLProtocol` subclass used to intercept requests issued by the client
/// under test. Mirrors the pattern in `PKEHTTPClientTests.swift`. Tests
/// reset `handler` in `tearDown` to keep cases independent.
///
/// `bodyFromRequest(_:)` recovers the body for PUT/POST cases: when the
/// request carries an `httpBodyStream` (which `URLSession` substitutes for
/// `httpBody` on some paths) we drain the stream synchronously; when it
/// carries an `httpBody` we return it directly.
private final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotLoadFromNetwork))
            return
        }
        let (response, data) = handler(request)
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    /// Recover the body from a `URLRequest` regardless of whether
    /// `URLSession` materialised it as `httpBody` or `httpBodyStream`. The
    /// stream path applies to PUT bodies for non-trivial sizes, which the
    /// upload-blob test exercises.
    static func bodyFromRequest(_ request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var collected = Data()
        let bufferSize = 4096
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        while stream.hasBytesAvailable {
            let read = buffer.withUnsafeMutableBufferPointer { pointer -> Int in
                guard let base = pointer.baseAddress else { return 0 }
                return stream.read(base, maxLength: bufferSize)
            }
            if read <= 0 { break }
            collected.append(contentsOf: buffer.prefix(read))
        }
        return collected
    }
}
#endif
