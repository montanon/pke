// HLAM-150 — Identity endpoint tests.
//
// Drives `PKEHTTPClient.registerIdentity`, `.fetchIdentity`, and
// `.fetchIdentityBySigningKey` through the same `MockURLProtocol` pattern
// used by `PKEHTTPClientTests` to isolate the iOS surface from any live
// backend. Integration coverage against `make serve` is deferred until the
// FastAPI identity endpoints land under HLAM-47.
//
// AC coverage:
//   * happy-path round-trip for register + fetch
//   * 404 → `.notFound`
//   * 409 → `.duplicate(detail:)`
//   * base64url path-component shape on the lookup-by-signing-key call
//   * transport-error propagation as `.transport(URLError.Code)`.

#if canImport(Security)
import Foundation
import XCTest
import enum Crypto.P256
import PKECrypto
import PKEIdentity
import PKEProtocol
@testable import PKEHTTPClient

final class IdentityEndpointsTests: XCTestCase {

    override func tearDown() {
        MockURLProtocol.handler = nil
        MockURLProtocol.error = nil
        super.tearDown()
    }

    // MARK: AC #1 — register: correct request shape + parsed response

    func testRegisterIdentitySendsCorrectRequestAndParsesResponse() async throws {
        let baseURL = makeBaseURL()
        let endpoint = baseURL.appendingPathComponent("v1/identities")
        let signingKey = P256.Signing.PrivateKey().publicKey
        let encryptionKey = P256.KeyAgreement.PrivateKey().publicKey
        let displayName = "Alice's iPhone"
        let expected = makeIdentityFixture(
            signingPublicKey: signingKey.rawRepresentation,
            encryptionPublicKey: encryptionKey.rawRepresentation,
            displayName: displayName
        )

        MockURLProtocol.handler = { request in
            Self.assertRegisterRequest(
                request,
                endpoint: endpoint,
                signingKey: signingKey,
                encryptionKey: encryptionKey,
                displayName: displayName
            )
            return Self.jsonResponse(for: endpoint, status: 200, identity: expected)
        }

        let client = makeMockClient(baseURL: baseURL)
        let observed = try await client.registerIdentity(
            signingKey: signingKey,
            encryptionKey: encryptionKey,
            displayName: displayName
        )

        XCTAssertEqual(observed, expected)
    }

    /// Verifies the URL, method, Content-Type, and canonical JSON body of
    /// the outbound `registerIdentity` request. Extracted from
    /// `testRegisterIdentitySendsCorrectRequestAndParsesResponse` to keep
    /// the test body under SwiftLint's `function_body_length` ceiling.
    private static func assertRegisterRequest(
        _ request: URLRequest,
        endpoint: URL,
        signingKey: P256.Signing.PublicKey,
        encryptionKey: P256.KeyAgreement.PublicKey,
        displayName: String
    ) {
        XCTAssertEqual(request.url, endpoint)
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(
            request.value(forHTTPHeaderField: "Content-Type"),
            "application/json; charset=utf-8"
        )
        let body = requestBody(request)
        XCTAssertNotNil(body)
        guard let body, let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            XCTFail("request body was not parseable JSON")
            return
        }
        XCTAssertEqual(
            Set(object.keys),
            ["signing_public_key", "encryption_public_key", "display_name"]
        )
        XCTAssertEqual(object["display_name"] as? String, displayName)
        XCTAssertEqual(
            object["signing_public_key"] as? String,
            PKECrypto.Base64URL.encode(signingKey.rawRepresentation)
        )
        XCTAssertEqual(
            object["encryption_public_key"] as? String,
            PKECrypto.Base64URL.encode(encryptionKey.rawRepresentation)
        )
    }

    // MARK: AC #2 — fetch by id parses 200 response

    func testFetchIdentityReturnsParsedIdentityOn200() async throws {
        let baseURL = makeBaseURL()
        let identityID = "ident-abc-123"
        let endpoint = baseURL.appendingPathComponent("v1/identities/\(identityID)")
        let expected = makeIdentityFixture(id: identityID)

        MockURLProtocol.handler = { request in
            XCTAssertEqual(request.url, endpoint)
            XCTAssertEqual(request.httpMethod ?? "GET", "GET")
            return Self.jsonResponse(for: endpoint, status: 200, identity: expected)
        }

        let client = makeMockClient(baseURL: baseURL)
        let observed = try await client.fetchIdentity(identityID)
        XCTAssertEqual(observed, expected)
    }

    // MARK: AC #3 — 404 → .notFound via backend envelope

    func testFetchIdentityThrowsNotFoundOn404() async {
        let baseURL = makeBaseURL()
        let identityID = "ident-missing"
        let endpoint = baseURL.appendingPathComponent("v1/identities/\(identityID)")

        MockURLProtocol.handler = { _ in
            let body = Data(#"{"error":{"code":"not_found"}}"#.utf8)
            let response = HTTPURLResponse(
                url: endpoint,
                statusCode: 404,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, body)
        }

        let client = makeMockClient(baseURL: baseURL)
        do {
            _ = try await client.fetchIdentity(identityID)
            XCTFail("expected .notFound to throw")
        } catch let error as PKENetworkError {
            XCTAssertEqual(error, .notFound)
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    // MARK: AC #4 — base64url path component (URL-safe, unpadded)

    func testFetchIdentityBySigningKeyEncodesKeyAsBase64UrlPathComponent() async throws {
        let baseURL = makeBaseURL()

        // 64 bytes of non-trivial content guarantees the standard-alphabet
        // base64 encoding would contain '+' and/or '/' for at least one
        // byte pattern — the assertion below pins the URL-safe alphabet.
        let keyBytes = Data((0..<64).map { UInt8($0 &* 7 &+ 3) })
        let expectedEncoded = PKECrypto.Base64URL.encode(keyBytes)
        XCTAssertFalse(expectedEncoded.contains("="))
        XCTAssertFalse(expectedEncoded.contains("+"))
        XCTAssertFalse(expectedEncoded.contains("/"))

        let endpoint = baseURL
            .appendingPathComponent("v1/identities/by-signing-key/\(expectedEncoded)")
        let expected = makeIdentityFixture(signingPublicKey: keyBytes)

        MockURLProtocol.handler = { request in
            // Compare path strings rather than full URLs so a trailing slash
            // or query difference cannot hide a missing or wrong segment.
            XCTAssertEqual(request.url?.path, endpoint.path)
            XCTAssertTrue(request.url?.path.contains(expectedEncoded) ?? false)
            // Percent-encoding must not have been applied — `=` and `/` would
            // turn into `%3D` / `%2F`, which we explicitly do not want.
            XCTAssertFalse(request.url?.absoluteString.contains("%3D") ?? true)
            XCTAssertFalse(request.url?.absoluteString.contains("%2F") ?? true)
            return Self.jsonResponse(for: endpoint, status: 200, identity: expected)
        }

        let client = makeMockClient(baseURL: baseURL)
        let observed = try await client.fetchIdentityBySigningKey(keyBytes)
        XCTAssertEqual(observed, expected)
    }

    // MARK: AC #5 — 409 → .duplicate(detail:)

    func testRegisterIdentityMapsDuplicateError() async {
        let baseURL = makeBaseURL()
        let endpoint = baseURL.appendingPathComponent("v1/identities")
        let detail = "signing_public_key already registered"

        MockURLProtocol.handler = { _ in
            let payload = #"{"error":{"code":"duplicate","detail":"\#(detail)"}}"#
            let body = Data(payload.utf8)
            let response = HTTPURLResponse(
                url: endpoint,
                statusCode: 409,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, body)
        }

        let client = makeMockClient(baseURL: baseURL)
        do {
            _ = try await client.registerIdentity(
                signingKey: P256.Signing.PrivateKey().publicKey,
                encryptionKey: P256.KeyAgreement.PrivateKey().publicKey,
                displayName: nil
            )
            XCTFail("expected .duplicate to throw")
        } catch let error as PKENetworkError {
            XCTAssertEqual(error, .duplicate(detail: detail))
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    // MARK: AC #6 — transport failure surfaces as .transport(URLError.Code)

    func testTransportFailurePropagatesAsTransportCase() async {
        let baseURL = makeBaseURL()
        let identityID = "ident-x"

        MockURLProtocol.handler = nil
        MockURLProtocol.error = URLError(.notConnectedToInternet)

        let client = makeMockClient(baseURL: baseURL)
        do {
            _ = try await client.fetchIdentity(identityID)
            XCTFail("expected .transport to throw")
        } catch let error as PKENetworkError {
            XCTAssertEqual(error, .transport(.notConnectedToInternet))
        } catch {
            XCTFail("unexpected error type: \(error)")
        }

        MockURLProtocol.error = nil
    }

    // MARK: - Helpers

    private func makeBaseURL() -> URL {
        // swiftlint:disable:next force_unwrapping
        URL(string: "https://pke.test.invalid")!
    }

    private func makeIdentity() -> DeviceIdentity {
        DeviceIdentity(
            signingKey: P256.Signing.PrivateKey(),
            agreementKey: P256.KeyAgreement.PrivateKey()
        )
    }

    private func makeMockClient(baseURL: URL) -> PKEHTTPClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        return PKEHTTPClient(
            baseURL: baseURL,
            identity: makeIdentity(),
            configuration: configuration
        )
    }

    private func makeIdentityFixture(
        id: String = "ident-default-001",
        signingPublicKey: Data? = nil,
        encryptionPublicKey: Data? = nil,
        displayName: String? = nil
    ) -> Identity {
        Identity(
            id: id,
            signingPublicKey: signingPublicKey ?? Data(repeating: 0xAA, count: 64),
            encryptionPublicKey: encryptionPublicKey ?? Data(repeating: 0xBB, count: 64),
            displayName: displayName,
            createdAt: ISO8601UTCDate(Date(timeIntervalSince1970: 0))
        )
    }

    /// Read the request body whether `URLSession` handed it to `URLProtocol`
    /// as `httpBody` directly or as a stream via `httpBodyStream`. Real
    /// devices use the stream form, so the stream branch is the load-
    /// bearing one in CI.
    private static func requestBody(_ request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else {
            return nil
        }
        stream.open()
        defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 4096)
        var collected = Data()
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 {
                break
            }
            collected.append(buffer, count: read)
        }
        return collected
    }

    private static func jsonResponse(
        for url: URL,
        status: Int,
        identity: Identity
    ) -> (HTTPURLResponse, Data) {
        let encoder = JSONEncoder()
        let body: Data
        do {
            body = try encoder.encode(identity)
        } catch {
            // Fixture encoding should never fail under test; surface the
            // failure as an empty body so the call site asserts on it.
            body = Data()
        }
        let response = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )
        // swiftlint:disable:next force_unwrapping
        return (response!, body)
    }
}

// MARK: - URLProtocol mock

/// Local `URLProtocol` for the endpoint tests. Carries both a success
/// `handler` and an `error` channel so transport-failure cases can fail
/// the loader without constructing a synthetic response.
private final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?
    static var error: URLError?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        if let error = Self.error {
            client?.urlProtocol(self, didFailWithError: error)
            return
        }
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
#endif
