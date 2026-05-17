// Cross-language canonical-bytes parity for the 5 Codable protocol payloads.
//
// For every typed payload the test:
//   1. loads `Resources/examples/<name>.example.json` (committed under
//      `context/examples/`),
//   2. decodes through the matching `Codable` model,
//   3. converts to `JSONValue` via `toJSONValue()` and runs it through
//      `CanonicalJSON.encode`,
//   4. asserts byte-equivalence against
//      `Resources/examples/<name>.canonical-bytes` (same directory).
//
// The fixtures are co-committed with the backend's
// `src/backend/tests/protocol/test_canonical_bytes_parity.py`, which runs
// the same round-trip through the Pydantic models — so a mismatch on
// either side surfaces as a CI failure on whichever runtime regresses.
//
// `freeze` and `report` ledger-payload variants live in the same fixture
// directory but have no typed Codable model in this story and no
// canonical-bytes fixture yet, so they are not exercised here.

import XCTest
@testable import PKECrypto
@testable import PKEProtocol

final class RoundTripParityTests: XCTestCase {

    func test_snapshot_commitment_roundtrip_matches_canonical_bytes() throws {
        let example = try loadExample("snapshot_commitment")
        let model = try JSONDecoder().decode(SnapshotCommitment.self, from: example)
        try assertCanonicalParity(model, fixtureName: "snapshot_commitment")
    }

    func test_witness_attestation_roundtrip_matches_canonical_bytes() throws {
        let example = try loadExample("witness_attestation")
        let model = try JSONDecoder().decode(WitnessAttestation.self, from: example)
        try assertCanonicalParity(model, fixtureName: "witness_attestation")
    }

    func test_ledger_entry_roundtrip_matches_canonical_bytes() throws {
        let example = try loadExample("ledger_entry")
        let model = try JSONDecoder().decode(LedgerEntry.self, from: example)
        XCTAssertEqual(model.eventType, .snapshotCommitted)
        try assertCanonicalParity(model, fixtureName: "ledger_entry")
    }

    func test_key_grant_roundtrip_matches_canonical_bytes() throws {
        let example = try loadExample("key_grant")
        let model = try JSONDecoder().decode(KeyGrant.self, from: example)
        try assertCanonicalParity(model, fixtureName: "key_grant")
    }

    func test_verification_report_roundtrip_matches_canonical_bytes() throws {
        let example = try loadExample("verification_report")
        let model = try JSONDecoder().decode(VerificationReport.self, from: example)
        try assertCanonicalParity(model, fixtureName: "verification_report")
    }

    func test_unknown_top_level_key_is_rejected() throws {
        let example = try loadExample("snapshot_commitment")
        let mutated = try injectExtraKey(into: example, key: "rogue_field", value: "x")
        XCTAssertThrowsError(try JSONDecoder().decode(SnapshotCommitment.self, from: mutated)) { error in
            guard case DecodingError.dataCorrupted(let context) = error else {
                XCTFail("expected DecodingError.dataCorrupted, got \(error)")
                return
            }
            XCTAssertTrue(
                context.debugDescription.contains("rogue_field"),
                "debug description should mention the rogue key, got: \(context.debugDescription)"
            )
        }
    }

    func test_iso8601_rejects_missing_z_suffix() {
        let raw = Data("\"2026-05-15T00:00:00\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(ISO8601UTCDate.self, from: raw))
    }

    func test_iso8601_rejects_non_utc_offset() {
        let raw = Data("\"2026-05-15T00:00:00+02:00\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(ISO8601UTCDate.self, from: raw))
    }

    func test_iso8601_rejects_unpadded_month() {
        let raw = Data("\"2026-5-15T00:00:00Z\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(ISO8601UTCDate.self, from: raw))
    }

    func test_base64url_rejects_padded_input() {
        // "AAAA=" — padded base64url string in a Base64UrlData slot.
        let raw = Data("\"AAAA=\"".utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(Base64UrlData.self, from: raw)) { error in
            guard case DecodingError.dataCorrupted(let context) = error else {
                XCTFail("expected DecodingError.dataCorrupted, got \(error)")
                return
            }
            XCTAssertTrue(
                context.debugDescription.contains("padded"),
                "debug description should mention 'padded', got: \(context.debugDescription)"
            )
        }
    }

    // MARK: - Helpers

    private func assertCanonicalParity(_ model: some Encodable, fixtureName: String) throws {
        let value = try model.toJSONValue()
        let canonical = try CanonicalJSON.encode(value)
        let expected = try loadCanonicalBytes(fixtureName)
        XCTAssertEqual(
            canonical,
            expected,
            "canonical bytes mismatch for \(fixtureName); got \(diagnosticString(canonical))"
        )
    }

    private func loadExample(_ name: String) throws -> Data {
        let url = try resourceURL(file: "\(name).example", ext: "json")
        return try Data(contentsOf: url)
    }

    private func loadCanonicalBytes(_ name: String) throws -> Data {
        let url = try resourceURL(file: name, ext: "canonical-bytes")
        return try Data(contentsOf: url)
    }

    private func resourceURL(file: String, ext: String) throws -> URL {
        if let url = Bundle.module.url(
            forResource: file,
            withExtension: ext,
            subdirectory: "examples"
        ) {
            return url
        }
        // Fallback when SwiftPM flattens copied resources without the subdirectory.
        if let url = Bundle.module.url(forResource: file, withExtension: ext) {
            return url
        }
        throw XCTSkip("resource examples/\(file).\(ext) not present in test bundle")
    }

    private func injectExtraKey(into json: Data, key: String, value: String) throws -> Data {
        guard var text = String(data: json, encoding: .utf8) else {
            throw NSError(domain: "RoundTripParityTests", code: 1)
        }
        // Insert as the first key inside the top-level object.
        guard let openBrace = text.firstIndex(of: "{") else {
            throw NSError(domain: "RoundTripParityTests", code: 2)
        }
        let insertAt = text.index(after: openBrace)
        let injection = "\"\(key)\":\"\(value)\","
        text.insert(contentsOf: injection, at: insertAt)
        return Data(text.utf8)
    }

    private func diagnosticString(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? "<non-utf8 \(data.count) bytes>"
    }
}
