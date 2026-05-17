// HLAM-152 — tests for the attestation batch upload endpoint.
//
// Mirrors the MockURLProtocol pattern from `PKEHTTPClientTests` (HLAM-146):
// a per-test URLProtocol handler is installed on a custom
// `URLSessionConfiguration`, and the actor under test is initialised via
// the internal three-argument initialiser that accepts the configuration.
//
// Coverage maps to HLAM-152 AC #5:
//   1. canonical-JSON POST + body shape for a happy-path 200,
//   2. empty-batch pre-flight rejection (no request is issued),
//   3. oversize-batch pre-flight rejection (no request is issued),
//   4. partial-success parsing on a 207 multi-status response,
//   5. hard rejection envelope mapping (409 → `.duplicate`),
//   6. transport-error propagation through `URLError.Code`.
//
// Integration tests against `make serve` are deferred until HLAM-47 lands
// the backend `/v1/snapshots/{id}/attestations` endpoint.

#if canImport(Security)
import Foundation
import XCTest
import enum Crypto.P256
import PKECrypto
import PKEIdentity
import PKEProtocol
@testable import PKEHTTPClient

final class AttestationEndpointsTests: XCTestCase {

    override func tearDown() {
        MockURLProtocol.handler = nil
        MockURLProtocol.injectedError = nil
        super.tearDown()
    }

    // MARK: AC #5.1 — canonical POST + body shape

    func testUploadAttestationsSendsCorrectPostWithCanonicalBody() async throws {
        let baseURL = makeBaseURL()
        let snapshotId = "snap-001"
        let expectedURL = baseURL.appendingPathComponent("v1/snapshots/\(snapshotId)/attestations")
        let attestations = [
            makeAttestation(snapshotId: snapshotId, nonceByte: 0x01),
            makeAttestation(snapshotId: snapshotId, nonceByte: 0x02)
        ]

        let captured = CapturedRequest()
        MockURLProtocol.handler = { request in
            captured.record(request)
            let response = HTTPURLResponse(
                // swiftlint:disable:next force_unwrapping
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )
            let body = Data(#"{"accepted":[],"rejected":[]}"#.utf8)
            // swiftlint:disable:next force_unwrapping
            return (response!, body)
        }

        let client = makeMockClient(baseURL: baseURL)
        let result = try await client.uploadAttestations(snapshotId, attestations)

        XCTAssertEqual(result.accepted, [])
        XCTAssertEqual(result.rejected, [])

        let request = try XCTUnwrap(captured.request)
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url, expectedURL)
        XCTAssertEqual(
            request.value(forHTTPHeaderField: "Content-Type"),
            RequestSigning.canonicalJSONContentType
        )

        // URLProtocol mocks observe the body via `httpBodyStream`, not
        // `httpBody`; drain it before decoding.
        let bodyData = try XCTUnwrap(captured.bodyData)
        let decodedRoot = try JSONSerialization.jsonObject(with: bodyData)
        let rootObject = try XCTUnwrap(decodedRoot as? [String: Any])
        let decodedAttestations = try XCTUnwrap(rootObject["attestations"] as? [[String: Any]])
        XCTAssertEqual(decodedAttestations.count, attestations.count)
        XCTAssertEqual(rootObject.count, 1)
        XCTAssertNotNil(rootObject["attestations"])
    }

    // MARK: AC #5.2 — empty batch is rejected pre-flight

    func testUploadAttestationsRejectsEmptyBatch() async {
        let baseURL = makeBaseURL()
        MockURLProtocol.handler = { _ in
            XCTFail("pre-flight should reject empty batch without issuing a request")
            let response = HTTPURLResponse(
                url: baseURL,
                statusCode: 500,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, Data())
        }

        let client = makeMockClient(baseURL: baseURL)
        do {
            _ = try await client.uploadAttestations("snap-001", [])
            XCTFail("expected malformedPayload error")
        } catch let error as PKENetworkError {
            guard case .malformedPayload(let detail) = error else {
                XCTFail("expected .malformedPayload, got \(error)")
                return
            }
            XCTAssertTrue(detail.contains("empty"), "unexpected detail: \(detail)")
        } catch {
            XCTFail("expected PKENetworkError, got \(error)")
        }
    }

    // MARK: AC #5.3 — oversize batch is rejected pre-flight

    func testUploadAttestationsRejectsOversizeBatch() async {
        let baseURL = makeBaseURL()
        MockURLProtocol.handler = { _ in
            XCTFail("pre-flight should reject oversize batch without issuing a request")
            let response = HTTPURLResponse(
                url: baseURL,
                statusCode: 500,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, Data())
        }

        let oversize = (0..<51).map { index in
            makeAttestation(snapshotId: "snap-001", nonceByte: UInt8(index % 256))
        }
        let client = makeMockClient(baseURL: baseURL)
        do {
            _ = try await client.uploadAttestations("snap-001", oversize)
            XCTFail("expected malformedPayload error")
        } catch let error as PKENetworkError {
            guard case .malformedPayload(let detail) = error else {
                XCTFail("expected .malformedPayload, got \(error)")
                return
            }
            XCTAssertTrue(detail.contains("50"), "unexpected detail: \(detail)")
            XCTAssertTrue(detail.contains("51"), "expected count in detail, got: \(detail)")
        } catch {
            XCTFail("expected PKENetworkError, got \(error)")
        }
    }

    // MARK: AC #5.4 — partial-success response parses correctly

    func testUploadAttestationsParsesPartialSuccessResponse() async throws {
        let baseURL = makeBaseURL()
        let snapshotId = "snap-001"
        let bodyJSON = #"""
        {
          "accepted": ["AQEBAQEBAQEBAQEBAQEBAQ"],
          "rejected": [
            {"session_nonce": "AgICAgICAgICAgICAgICAg", "reason": "session_nonce already committed"},
            {"session_nonce": "AwMDAwMDAwMDAwMDAwMDAw", "reason": "signature_invalid"}
          ]
        }
        """#

        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                // swiftlint:disable:next force_unwrapping
                url: request.url!,
                statusCode: 207,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, Data(bodyJSON.utf8))
        }

        let client = makeMockClient(baseURL: baseURL)
        let result = try await client.uploadAttestations(snapshotId, [
            makeAttestation(snapshotId: snapshotId, nonceByte: 0x01),
            makeAttestation(snapshotId: snapshotId, nonceByte: 0x02),
            makeAttestation(snapshotId: snapshotId, nonceByte: 0x03)
        ])

        XCTAssertEqual(result.accepted, ["AQEBAQEBAQEBAQEBAQEBAQ"])
        XCTAssertEqual(result.rejected.count, 2)
        XCTAssertEqual(result.rejected[0].sessionNonce, "AgICAgICAgICAgICAgICAg")
        XCTAssertEqual(result.rejected[0].reason, "session_nonce already committed")
        XCTAssertEqual(result.rejected[1].sessionNonce, "AwMDAwMDAwMDAwMDAwMDAw")
        XCTAssertEqual(result.rejected[1].reason, "signature_invalid")
    }

    // MARK: AC #5.5 — hard rejection envelope mapping (409 → .duplicate)

    func testUploadAttestationsMapsBackendDuplicateError() async {
        let baseURL = makeBaseURL()
        let envelope = #"""
        {"error":{"code":"duplicate","detail":"session_nonce already committed"}}
        """#

        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                // swiftlint:disable:next force_unwrapping
                url: request.url!,
                statusCode: 409,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, Data(envelope.utf8))
        }

        let client = makeMockClient(baseURL: baseURL)
        do {
            _ = try await client.uploadAttestations("snap-001", [
                makeAttestation(snapshotId: "snap-001", nonceByte: 0x01)
            ])
            XCTFail("expected duplicate error")
        } catch let error as PKENetworkError {
            guard case .duplicate(let detail) = error else {
                XCTFail("expected .duplicate, got \(error)")
                return
            }
            XCTAssertEqual(detail, "session_nonce already committed")
        } catch {
            XCTFail("expected PKENetworkError, got \(error)")
        }
    }

    // MARK: AC #5.6 — transport failure surfaces as .transport(code)

    func testUploadAttestationsMapsTransportFailure() async {
        let baseURL = makeBaseURL()

        MockURLProtocol.injectedError = URLError(.notConnectedToInternet)
        MockURLProtocol.handler = { _ in
            XCTFail("injected URLError should fail loading before the handler runs")
            let response = HTTPURLResponse(
                url: baseURL,
                statusCode: 500,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )
            // swiftlint:disable:next force_unwrapping
            return (response!, Data())
        }

        let client = makeMockClient(baseURL: baseURL)
        do {
            _ = try await client.uploadAttestations("snap-001", [
                makeAttestation(snapshotId: "snap-001", nonceByte: 0x01)
            ])
            XCTFail("expected transport error")
        } catch let error as PKENetworkError {
            guard case .transport(let code) = error else {
                XCTFail("expected .transport, got \(error)")
                return
            }
            XCTAssertEqual(code, .notConnectedToInternet)
        } catch {
            XCTFail("expected PKENetworkError, got \(error)")
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

    /// Plausible-but-unsigned `WitnessAttestation` used by tests that only
    /// inspect the wire shape (not the inline signature). The
    /// `witnessSignature` slot is empty because no test reads it — the
    /// outer batch is what's under test, not signature re-verification
    /// (which lives under HLAM-149).
    private func makeAttestation(snapshotId: String, nonceByte: UInt8) -> WitnessAttestation {
        WitnessAttestation(
            version: "0.1",
            snapshotId: snapshotId,
            ciphertextHash: Data(repeating: 0xAB, count: 32),
            sessionNonce: Data(repeating: nonceByte, count: 16),
            ownerSigningPublicKey: Data(repeating: 0xCD, count: 64),
            witnessSigningPublicKey: Data(repeating: 0xEF, count: 64),
            witnessTimestamp: ISO8601UTCDate(Date(timeIntervalSince1970: 1_700_000_500)),
            transport: "bluetooth",
            proximityClaim: WitnessAttestation.ProximityClaim(
                method: "rssi",
                exactLocationPublic: false
            ),
            witnessSignature: Data()
        )
    }
}

// MARK: - Captured-request helper

/// Lock-protected slot used to surface the request the mock saw back to
/// the test body. Needed because `MockURLProtocol.handler` runs on a
/// URLSession-internal queue.
private final class CapturedRequest: @unchecked Sendable {

    private let lock = NSLock()
    private var stored: URLRequest?
    private var storedBody: Data?

    var request: URLRequest? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    var bodyData: Data? {
        lock.lock()
        defer { lock.unlock() }
        return storedBody
    }

    func record(_ request: URLRequest) {
        lock.lock()
        defer { lock.unlock() }
        stored = request
        // URLSession serialises the body through `httpBodyStream` when the
        // request is reissued to the protocol class, so drain that stream
        // here. Fall back to `httpBody` for any test path that bypasses
        // the stream conversion.
        if let stream = request.httpBodyStream {
            storedBody = Self.drain(stream)
        } else {
            storedBody = request.httpBody
        }
    }

    private static func drain(_ stream: InputStream) -> Data {
        stream.open()
        defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 4096)
        var out = Data()
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            out.append(buffer, count: read)
        }
        return out
    }
}

// MARK: - URLProtocol mock

/// Per-target copy of the `MockURLProtocol` used by `PKEHTTPClientTests`.
/// Kept file-private so each test file owns its own injection point with
/// no cross-test coupling.
private final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?
    /// If set, the protocol fails the load with this error instead of
    /// returning the handler's `(response, data)` tuple. Cleared between
    /// tests via `tearDown`.
    static var injectedError: URLError?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        if let error = Self.injectedError {
            Self.injectedError = nil
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
