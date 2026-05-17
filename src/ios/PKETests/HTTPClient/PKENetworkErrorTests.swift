// HLAM-154 — error-taxonomy tests.
//
// Exercises (1) the backend `error.code` → enum mapping (the full set
// plus the unknown-code fallthrough), (2) `LocalizedError` text presence
// for every case, and (3) `Equatable` correctness around the
// associated-value cases that other parts of the client compare against.

#if canImport(Security)
import Foundation
import XCTest
import PKECrypto
@testable import PKEHTTPClient

final class PKENetworkErrorTests: XCTestCase {

    // MARK: AC #1 / #2 — backend code → enum mapping

    func testMappingForEveryKnownBackendCode() {
        let cases: [BackendMappingCase] = [
            BackendMappingCase("malformed_payload", "missing field", .malformedPayload(detail: "missing field")),
            BackendMappingCase("not_found", "", .notFound),
            BackendMappingCase("duplicate", "session_nonce reused", .duplicate(detail: "session_nonce reused")),
            BackendMappingCase("signature_invalid", "", .signatureInvalid),
            BackendMappingCase("hash_mismatch", "", .hashMismatch),
            BackendMappingCase("internal_server_error", "", .internalServerError)
        ]
        for sample in cases {
            let envelope = BackendErrorEnvelope(
                error: BackendErrorBody(code: sample.code, detail: sample.detail.isEmpty ? nil : sample.detail)
            )
            XCTAssertEqual(
                PKENetworkError.from(backendError: envelope),
                sample.expected,
                "code '\(sample.code)' did not map to expected case"
            )
        }
    }

    func testUnknownBackendCodeFallsThroughToInternalServerError() {
        let envelope = BackendErrorEnvelope(
            error: BackendErrorBody(code: "definitely_not_a_real_code_yet", detail: "future")
        )
        XCTAssertEqual(
            PKENetworkError.from(backendError: envelope),
            .internalServerError
        )
    }

    // MARK: AC #1 — JSON shape of the backend envelope is decodable as-is

    func testBackendEnvelopeDecodesFromExpectedJSONShape() throws {
        let json = Data("""
        {"error":{"code":"duplicate","detail":"already submitted"}}
        """.utf8)
        let envelope = try JSONDecoder().decode(BackendErrorEnvelope.self, from: json)
        XCTAssertEqual(envelope.error.code, "duplicate")
        XCTAssertEqual(envelope.error.detail, "already submitted")
    }

    func testBackendEnvelopeAcceptsMissingDetail() throws {
        let json = Data("""
        {"error":{"code":"not_found"}}
        """.utf8)
        let envelope = try JSONDecoder().decode(BackendErrorEnvelope.self, from: json)
        XCTAssertEqual(envelope.error.code, "not_found")
        XCTAssertNil(envelope.error.detail)
    }

    // MARK: AC #3 — LocalizedError surface

    func testEveryCaseProvidesANonEmptyLocalizedDescription() {
        let representatives: [PKENetworkError] = [
            .malformedPayload(detail: "x"),
            .notFound,
            .duplicate(detail: "x"),
            .signatureInvalid,
            .hashMismatch,
            .internalServerError,
            .transport(.notConnectedToInternet),
            .uploadFailed(reason: "x"),
            .verificationFailed(.signatureVerification),
            .encoding(reason: "x"),
            .decoding(reason: "x")
        ]
        for error in representatives {
            XCTAssertFalse(
                (error.errorDescription ?? "").isEmpty,
                "case \(error) returned empty errorDescription"
            )
            XCTAssertFalse(
                error.localizedDescription.isEmpty,
                "case \(error) returned empty localizedDescription"
            )
        }
    }

    // MARK: Equatable — associated values must participate

    func testEquatableDistinguishesAssociatedValues() {
        XCTAssertEqual(
            PKENetworkError.malformedPayload(detail: "x"),
            PKENetworkError.malformedPayload(detail: "x")
        )
        XCTAssertNotEqual(
            PKENetworkError.malformedPayload(detail: "x"),
            PKENetworkError.malformedPayload(detail: "y")
        )
        XCTAssertEqual(
            PKENetworkError.verificationFailed(.signatureVerification),
            PKENetworkError.verificationFailed(.signatureVerification)
        )
        XCTAssertNotEqual(
            PKENetworkError.verificationFailed(.signatureVerification),
            PKENetworkError.verificationFailed(.signatureFormat(reason: "x"))
        )
        XCTAssertNotEqual(PKENetworkError.notFound, PKENetworkError.signatureInvalid)
    }
}

/// Single-row fixture for the backend `error.code` → enum mapping table —
/// extracted to a named struct because SwiftLint's `large_tuple` rule
/// caps named-tuple sizes at 2.
private struct BackendMappingCase {
    let code: String
    let detail: String
    let expected: PKENetworkError

    init(_ code: String, _ detail: String, _ expected: PKENetworkError) {
        self.code = code
        self.detail = detail
        self.expected = expected
    }
}
#endif
