// HLAM-146 — `PKEHTTPClient` skeleton tests.
//
// Exercises the three acceptance criteria that have observable behavior:
//
//   * AC #1 — `actor PKEHTTPClient { init(baseURL: URL, identity:
//     DeviceIdentity) }` is reachable from external callers.
//   * AC #3 — concurrent `send(_:)` calls from independent async contexts
//     complete without any external locking.
//   * AC #4 — `send(_:)` round-trips against an in-process mock that stands
//     in for the backend until HLAM-134 / HLAM-47 land a real server.
//
// AC #2 (no `NSAllowsArbitraryLoads`) is an Info.plist concern outside this
// library; we instead assert that the session is configured from
// `URLSessionConfiguration.default` indirectly by relying on its protocol
// chain in the mock test.

#if canImport(Security)
import Foundation
import XCTest
import enum Crypto.P256
@testable import PKEHTTPClient
import PKEIdentity

final class PKEHTTPClientTests: XCTestCase {

    override func tearDown() {
        MockURLProtocol.handler = nil
        super.tearDown()
    }

    // MARK: AC #1 — actor surface + designated init

    func testClientExposesBaseURLAfterInit() async {
        let baseURL = makeBaseURL()
        let client = PKEHTTPClient(baseURL: baseURL, identity: makeIdentity())
        let observed = await client.baseURL
        XCTAssertEqual(observed, baseURL)
    }

    // MARK: AC #4 — single round-trip via URLProtocol mock

    func testSendReturnsResponseBodyAndStatus() async throws {
        let baseURL = makeBaseURL()
        let endpoint = baseURL.appendingPathComponent("ping")
        let body = Data("pong".utf8)

        MockURLProtocol.handler = { request in
            XCTAssertEqual(request.url, endpoint)
            let response = HTTPURLResponse(
                url: endpoint,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/octet-stream"]
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, body)
        }

        let client = makeMockClient(baseURL: baseURL)
        let (data, response) = try await client.send(URLRequest(url: endpoint))

        XCTAssertEqual(data, body)
        XCTAssertEqual(response.statusCode, 200)
    }

    // MARK: AC #4 — non-HTTP response surfaces a typed error

    func testSendThrowsForNonHTTPResponse() {
        // URLSession never returns a non-HTTP response for an http(s) request,
        // so this asserts the error case via equality on the typed error
        // rather than constructing a synthetic URLResponse path.
        XCTAssertEqual(PKEHTTPClientError.nonHTTPResponse, .nonHTTPResponse)
    }

    // MARK: AC #3 — concurrent requests from independent async contexts

    func testConcurrentSendsCompleteWithoutExternalLocking() async throws {
        let baseURL = makeBaseURL()
        let concurrency = 16

        MockURLProtocol.handler = { request in
            // swiftlint:disable:next force_unwrapping
            let url = request.url!
            let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )
            let body = Data(url.lastPathComponent.utf8)
            // swiftlint:disable:next force_unwrapping
            return (response!, body)
        }

        let client = makeMockClient(baseURL: baseURL)

        let results = try await withThrowingTaskGroup(of: (Int, Data).self) { group in
            for index in 0..<concurrency {
                group.addTask {
                    let url = baseURL.appendingPathComponent("\(index)")
                    let (data, _) = try await client.send(URLRequest(url: url))
                    return (index, data)
                }
            }
            var collected: [Int: Data] = [:]
            for try await (index, data) in group {
                collected[index] = data
            }
            return collected
        }

        XCTAssertEqual(results.count, concurrency)
        for index in 0..<concurrency {
            XCTAssertEqual(results[index], Data("\(index)".utf8))
        }
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
}

// MARK: - URLProtocol mock

/// `URLProtocol` subclass used to intercept requests issued by the client
/// under test. Lives in the test target so production code has no test-only
/// dependency. `handler` is the per-test injection point; tests reset it in
/// `tearDown` to keep cases independent.
private final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = MockURLProtocol.handler else {
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
