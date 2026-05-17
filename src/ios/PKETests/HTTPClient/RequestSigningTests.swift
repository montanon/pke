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
import PKECrypto
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

    // MARK: - Helpers

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

// MARK: - Fixture

/// Two-field `Encodable` whose declared order (`zeta` before `alpha`)
/// differs from the canonical order, so any failure to sort keys surfaces
/// immediately.
private struct SampleBody: Encodable {
    let zeta: Int
    let alpha: String
}
#endif
