// HLAM-153 — key-grant endpoint tests.
//
// Exercises the three `PKEHTTPClient` extension methods through a
// `URLProtocol` mock that stands in for the backend. Integration tests
// against `make serve` are deferred until HLAM-47 lands the backend route.

#if canImport(Security)
import Foundation
import XCTest
import enum Crypto.P256
import PKECrypto
import PKEIdentity
import PKEProtocol
@testable import PKEHTTPClient

final class KeyGrantEndpointsTests: XCTestCase {

    override func tearDown() {
        MockURLProtocol.handler = nil
        super.tearDown()
    }

    // MARK: createKeyGrant

    func testCreateKeyGrantSignsBodyAndPostsAndVerifiesResponse() async throws {
        let baseURL = makeBaseURL()
        let identity = makeIdentity()
        let unsigned = makeUnsignedKeyGrant(identity: identity)
        let serverResponse = try makeSignedKeyGrant(identity: identity)
        let responseBytes = try RequestSigning.canonicalBytes(serverResponse)
        let expectedURL = baseURL.appendingPathComponent(
            "v1/snapshots/\(unsigned.snapshotId)/key-grants"
        )

        let capture = RequestCapture()
        MockURLProtocol.handler = { request in
            capture.record(request)
            return (makeResponse(url: expectedURL, statusCode: 201), responseBytes)
        }

        let client = makeMockClient(baseURL: baseURL, identity: identity)
        let result = try await client.createKeyGrant(unsigned)

        XCTAssertEqual(capture.url, expectedURL)
        XCTAssertEqual(capture.method, "POST")
        let bodyBytes = try XCTUnwrap(capture.body)
        let bodyDict = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: bodyBytes) as? [String: Any]
        )
        let grantSignature = try XCTUnwrap(bodyDict["grant_signature"] as? String)
        XCTAssertFalse(grantSignature.isEmpty)
        XCTAssertEqual(bodyDict["snapshot_id"] as? String, unsigned.snapshotId)
        XCTAssertEqual(result, serverResponse)
    }

    func testCreateKeyGrantRejectsDuplicateError() async throws {
        let baseURL = makeBaseURL()
        let identity = makeIdentity()
        let unsigned = makeUnsignedKeyGrant(identity: identity)
        let envelopeBytes = try makeErrorEnvelopeBytes(
            code: "duplicate",
            detail: "key grant for recipient already exists"
        )
        let expectedURL = baseURL.appendingPathComponent(
            "v1/snapshots/\(unsigned.snapshotId)/key-grants"
        )
        MockURLProtocol.handler = { _ in
            (makeResponse(url: expectedURL, statusCode: 409), envelopeBytes)
        }

        let client = makeMockClient(baseURL: baseURL, identity: identity)
        do {
            _ = try await client.createKeyGrant(unsigned)
            XCTFail("expected createKeyGrant to throw")
        } catch let error as PKENetworkError {
            guard case .duplicate(let detail) = error else {
                XCTFail("expected .duplicate, got \(error)")
                return
            }
            XCTAssertEqual(detail, "key grant for recipient already exists")
        }
    }

    func testCreateKeyGrantRejectsTamperedResponse() async throws {
        let baseURL = makeBaseURL()
        let identity = makeIdentity()
        let unsigned = makeUnsignedKeyGrant(identity: identity)
        let goodSigned = try makeSignedKeyGrant(identity: identity)
        let tamperedBytes = try tamperSnapshotIdInJSON(of: goodSigned)
        let expectedURL = baseURL.appendingPathComponent(
            "v1/snapshots/\(unsigned.snapshotId)/key-grants"
        )
        MockURLProtocol.handler = { _ in
            (makeResponse(url: expectedURL, statusCode: 201), tamperedBytes)
        }

        let client = makeMockClient(baseURL: baseURL, identity: identity)
        do {
            _ = try await client.createKeyGrant(unsigned)
            XCTFail("expected createKeyGrant to throw")
        } catch let error as PKENetworkError {
            guard case .verificationFailed(let cryptoError) = error else {
                XCTFail("expected .verificationFailed, got \(error)")
                return
            }
            XCTAssertEqual(cryptoError, .signatureVerification)
        }
    }

    // MARK: listKeyGrants

    func testListKeyGrantsReturnsAndVerifiesAll() async throws {
        let baseURL = makeBaseURL()
        let snapshotId = "snap-001"
        let grantA = try makeSignedKeyGrant(identity: makeIdentity(), grantId: "grant-A")
        let grantB = try makeSignedKeyGrant(identity: makeIdentity(), grantId: "grant-B")
        let grantC = try makeSignedKeyGrant(identity: makeIdentity(), grantId: "grant-C")
        let bodyBytes = try encodeKeyGrantListEnvelope([grantA, grantB, grantC])
        let expectedURL = baseURL.appendingPathComponent(
            "v1/snapshots/\(snapshotId)/key-grants"
        )

        let capture = RequestCapture()
        MockURLProtocol.handler = { request in
            capture.record(request)
            return (makeResponse(url: expectedURL, statusCode: 200), bodyBytes)
        }

        let client = makeMockClient(baseURL: baseURL, identity: makeIdentity())
        let grants = try await client.listKeyGrants(snapshotId: snapshotId)
        XCTAssertEqual(capture.method, "GET")
        XCTAssertEqual(capture.url, expectedURL)
        XCTAssertEqual(grants, [grantA, grantB, grantC])
    }

    func testListKeyGrantsRejectsBundleWithOneTamperedGrant() async throws {
        let baseURL = makeBaseURL()
        let snapshotId = "snap-001"
        let grantA = try makeSignedKeyGrant(identity: makeIdentity(), grantId: "grant-A")
        let grantB = try makeSignedKeyGrant(identity: makeIdentity(), grantId: "grant-B")
        let bodyBytes = try encodeKeyGrantListEnvelopeTamperingFirst([grantA, grantB])
        let expectedURL = baseURL.appendingPathComponent(
            "v1/snapshots/\(snapshotId)/key-grants"
        )
        MockURLProtocol.handler = { _ in
            (makeResponse(url: expectedURL, statusCode: 200), bodyBytes)
        }

        let client = makeMockClient(baseURL: baseURL, identity: makeIdentity())
        do {
            _ = try await client.listKeyGrants(snapshotId: snapshotId)
            XCTFail("expected listKeyGrants to throw")
        } catch let error as PKENetworkError {
            guard case .verificationFailed = error else {
                XCTFail("expected .verificationFailed, got \(error)")
                return
            }
        }
    }

    // MARK: fetchKeyGrant

    func testFetchKeyGrantOn404Throws_NotFound() async throws {
        let baseURL = makeBaseURL()
        let grantId = "grant-zzz"
        let envelopeBytes = try makeErrorEnvelopeBytes(code: "not_found", detail: nil)
        let expectedURL = baseURL.appendingPathComponent("v1/key-grants/\(grantId)")
        MockURLProtocol.handler = { _ in
            (makeResponse(url: expectedURL, statusCode: 404), envelopeBytes)
        }

        let client = makeMockClient(baseURL: baseURL, identity: makeIdentity())
        do {
            _ = try await client.fetchKeyGrant(grantId)
            XCTFail("expected fetchKeyGrant to throw")
        } catch let error as PKENetworkError {
            XCTAssertEqual(error, .notFound)
        }
    }

    func testFetchKeyGrantVerifiesInlineSignature() async throws {
        let baseURL = makeBaseURL()
        let signed = try makeSignedKeyGrant(identity: makeIdentity(), grantId: "grant-fetch")
        let bodyBytes = try RequestSigning.canonicalBytes(signed)
        let expectedURL = baseURL.appendingPathComponent("v1/key-grants/\(signed.grantId)")

        let capture = RequestCapture()
        MockURLProtocol.handler = { request in
            capture.record(request)
            return (makeResponse(url: expectedURL, statusCode: 200), bodyBytes)
        }

        let client = makeMockClient(baseURL: baseURL, identity: makeIdentity())
        let result = try await client.fetchKeyGrant(signed.grantId)
        XCTAssertEqual(capture.method, "GET")
        XCTAssertEqual(capture.url, expectedURL)
        XCTAssertEqual(result, signed)
    }
}

// MARK: - File-level helpers
//
// Kept outside the test class so the class body stays under the SwiftLint
// `type_body_length` budget. All helpers are private to this file.

private func makeBaseURL() -> URL {
    guard let url = URL(string: "https://pke.test.invalid") else {
        fatalError("static URL string must parse")
    }
    return url
}

private func makeIdentity() -> DeviceIdentity {
    DeviceIdentity(
        signingKey: P256.Signing.PrivateKey(),
        agreementKey: P256.KeyAgreement.PrivateKey()
    )
}

private func makeMockClient(baseURL: URL, identity: DeviceIdentity) -> PKEHTTPClient {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [MockURLProtocol.self]
    return PKEHTTPClient(baseURL: baseURL, identity: identity, configuration: configuration)
}

private func makeUnsignedKeyGrant(identity: DeviceIdentity) -> KeyGrant {
    KeyGrant(
        version: "0.1",
        grantId: "grant-pending",
        snapshotId: "snap-001",
        recipientEncryptionPublicKey: Data(repeating: 0xEF, count: 64),
        wrappedSnapshotKey: Data(repeating: 0x42, count: 48),
        wrappingAlgorithm: "AES-256-GCM",
        grantedBySigningPublicKey: identity.signingKey.publicKey.rawRepresentation,
        grantTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 1_700_001_000)),
        grantSignature: Data()
    )
}

/// Mirrors `ResponseVerificationTests.makeSignedKeyGrant`. Copied verbatim
/// because a shared test-helper module is HLAM-155 territory.
private func makeSignedKeyGrant(
    identity: DeviceIdentity,
    grantId: String = "grant-001",
    snapshotId: String = "snap-001"
) throws -> KeyGrant {
    let unsigned = KeyGrant(
        version: "0.1",
        grantId: grantId,
        snapshotId: snapshotId,
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

private func makeResponse(url: URL, statusCode: Int) -> HTTPURLResponse {
    guard let response = HTTPURLResponse(
        url: url,
        statusCode: statusCode,
        httpVersion: "HTTP/1.1",
        headerFields: ["Content-Type": "application/json; charset=utf-8"]
    ) else {
        fatalError("HTTPURLResponse failed to initialise for \(url)")
    }
    return response
}

private func makeErrorEnvelopeBytes(code: String, detail: String?) throws -> Data {
    var errorObject: [String: Any] = ["code": code]
    if let detail {
        errorObject["detail"] = detail
    }
    let envelope: [String: Any] = ["error": errorObject]
    return try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
}

/// Flip the `snapshot_id` value in a signed grant's JSON while preserving
/// `grant_signature`. The result is the in-transit-mutation case the
/// re-verification step is meant to catch.
private func tamperSnapshotIdInJSON(of grant: KeyGrant) throws -> Data {
    let goodBytes = try RequestSigning.canonicalBytes(grant)
    guard var object = try JSONSerialization.jsonObject(with: goodBytes) as? [String: Any] else {
        throw TestHelperError.unexpectedJSONShape
    }
    guard let original = object["snapshot_id"] as? String else {
        throw TestHelperError.unexpectedJSONShape
    }
    object["snapshot_id"] = original + "X"
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

private func encodeKeyGrantListEnvelope(_ grants: [KeyGrant]) throws -> Data {
    let elements: [Any] = try grants.map { grant in
        let bytes = try RequestSigning.canonicalBytes(grant)
        return try JSONSerialization.jsonObject(with: bytes)
    }
    let envelope: [String: Any] = ["key_grants": elements]
    return try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
}

private func encodeKeyGrantListEnvelopeTamperingFirst(_ grants: [KeyGrant]) throws -> Data {
    guard let first = grants.first else {
        throw TestHelperError.unexpectedJSONShape
    }
    var elements: [Any] = []
    let firstBytes = try tamperSnapshotIdInJSON(of: first)
    guard let firstObject = try JSONSerialization.jsonObject(
        with: firstBytes
    ) as? [String: Any] else {
        throw TestHelperError.unexpectedJSONShape
    }
    elements.append(firstObject)
    for grant in grants.dropFirst() {
        let bytes = try RequestSigning.canonicalBytes(grant)
        elements.append(try JSONSerialization.jsonObject(with: bytes))
    }
    let envelope: [String: Any] = ["key_grants": elements]
    return try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
}

// MARK: - URLProtocol mock

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
}

// MARK: - Request capture

private final class RequestCapture: @unchecked Sendable {
    private(set) var url: URL?
    private(set) var method: String?
    private(set) var body: Data?

    func record(_ request: URLRequest) {
        self.url = request.url
        self.method = request.httpMethod
        // URLProtocol sees `httpBodyStream` (not `httpBody`) for in-memory bodies.
        if let body = request.httpBody {
            self.body = body
        } else if let stream = request.httpBodyStream {
            self.body = Self.drain(stream)
        }
    }

    private static func drain(_ stream: InputStream) -> Data {
        stream.open()
        defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 4096)
        var data = Data()
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 {
                break
            }
            data.append(buffer, count: read)
        }
        return data
    }
}

private enum TestHelperError: Error {
    case unexpectedJSONShape
}
#endif
