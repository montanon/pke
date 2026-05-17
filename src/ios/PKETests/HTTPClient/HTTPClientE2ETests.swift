// HLAM-155 — end-to-end HTTP round-trip tests against a live backend.
//
// Runs against the FastAPI service started by `make serve`. Tests gate
// themselves on backend reachability via `GET /health`: when the
// backend is not reachable (the typical CI case — iOS jobs run on
// macos-14 / ubuntu-22.04 runners without the Postgres + uvicorn stack)
// the test calls `XCTSkip` so the suite never produces false failures.
//
// Local usage:
//
//     # Terminal A — backend
//     make db && make serve
//
//     # Terminal B — iOS tests
//     PKE_BACKEND_URL=http://localhost:8000 make ios-test
//
// `PKE_BACKEND_URL` is honored if set; otherwise the suite probes
// `http://localhost:8000`. The probe is a single `GET /health` with a
// two-second timeout — a wedged backend skips, it does not stall.
//
// Scope notes:
//
// * **Implemented now** — AC #2 negative path that exercises the live
//   `GET` route on a missing snapshot. Current dev's backend has the
//   GET surface from HLAM-65 / 70 / 75 / 82, so this test runs end-to-
//   end against the wire today.
// * **Deferred** — the AC #1 full happy-path round-trip and the AC #2
//   duplicate-witness / hash-mismatch paths are `XCTSkip`-marked with
//   ticket references. Each unblocks once the relevant backend POST
//   endpoint (HLAM-139 / 141 / 142) and matching iOS HTTP-client
//   method (HLAM-150 / 151 / 152 / 153) land.
// * AC #4 — canonical-bytes byte-parity is HLAM-10's scope; not
//   duplicated here.

#if canImport(Security)
import Foundation
import XCTest
@testable import PKEHTTPClient

final class HTTPClientE2ETests: XCTestCase {

    // MARK: - Backend reachability

    private static var backendBaseURL: URL {
        let raw = ProcessInfo.processInfo.environment["PKE_BACKEND_URL"]
            ?? "http://localhost:8000"
        guard let url = URL(string: raw) else {
            preconditionFailure(
                "PKE_BACKEND_URL is set to a non-URL value: \(raw). " +
                "Use a value like http://localhost:8000 or unset the variable."
            )
        }
        return url
    }

    /// Probe `GET /health`. If the backend is unreachable or unhealthy,
    /// throws `XCTSkip` with a developer-facing reason. Time-boxed to
    /// two seconds so a wedged or slow CI runner does not stall the
    /// suite waiting for a connection it will never get.
    private func requireBackendReachable() async throws {
        let healthURL = Self.backendBaseURL.appendingPathComponent("health")
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 2
        configuration.timeoutIntervalForResource = 2
        let session = URLSession(configuration: configuration)

        do {
            let (_, response) = try await session.data(from: healthURL)
            guard let http = response as? HTTPURLResponse else {
                throw XCTSkip(
                    "Backend at \(Self.backendBaseURL) returned a non-HTTP " +
                    "response from /health; skipping E2E test."
                )
            }
            guard http.statusCode == 200 else {
                throw XCTSkip(
                    "Backend at \(Self.backendBaseURL) returned HTTP " +
                    "\(http.statusCode) on /health; skipping E2E test."
                )
            }
        } catch let error as XCTSkip {
            throw error
        } catch {
            throw XCTSkip(
                "Backend at \(Self.backendBaseURL) is not reachable " +
                "(\(error.localizedDescription)). To run locally: " +
                "`make db && make serve`, then re-run with " +
                "`PKE_BACKEND_URL=http://localhost:8000 make ios-test`."
            )
        }
    }

    // MARK: AC #1 — happy-path round-trip (deferred; see file header)

    func test_happyPath_identityToCommitToBlobToAttestationToKeyGrant() async throws {
        try await requireBackendReachable()
        throw XCTSkip(
            "Blocked on per-endpoint iOS client methods " +
            "(HLAM-150 / 151 / 152 / 153) and matching backend POST " +
            "endpoints (HLAM-139 / 141 / 142). Re-enable once those " +
            "are merged — the round-trip is identity → " +
            "POST /v1/snapshots → PUT blob → POST attestations → " +
            "POST key_grants → GET bundle."
        )
    }

    // MARK: AC #2 — negative path: 404 on missing snapshot (live)

    func test_getSnapshot_returns404ForUnknownID() async throws {
        try await requireBackendReachable()

        let unknownSnapshotURL = Self.backendBaseURL
            .appendingPathComponent("v1")
            .appendingPathComponent("snapshots")
            .appendingPathComponent("snap_does_not_exist")

        let (data, response) = try await URLSession.shared.data(from: unknownSnapshotURL)
        guard let http = response as? HTTPURLResponse else {
            XCTFail("Expected HTTPURLResponse; got \(type(of: response))")
            return
        }
        XCTAssertEqual(http.statusCode, 404, "Backend should 404 on unknown snapshot ID")

        // The backend's uniform error envelope (HLAM-143) is
        // `{"error": {"code": ..., "detail": ...}}`. If the body
        // decodes cleanly the mapper must turn `not_found` into
        // `PKENetworkError.notFound`. Early-development paths that
        // still return a raw FastAPI default are tolerated — the
        // statusCode check above is the hard assertion.
        if let envelope = try? JSONDecoder().decode(BackendErrorEnvelope.self, from: data) {
            XCTAssertEqual(
                PKENetworkError.from(backendError: envelope),
                .notFound,
                "Backend envelope code='\(envelope.error.code)' should map to .notFound"
            )
        }
    }

    // MARK: AC #2 — negative path: duplicate witness rejection (deferred)

    func test_duplicateWitnessRejection_surfacesAsDuplicate() async throws {
        try await requireBackendReachable()
        throw XCTSkip(
            "Blocked on POST /v1/snapshots/{id}/attestations (HLAM-141) " +
            "and the matching iOS client method (HLAM-152). The " +
            "duplicate-witness invariant is enforced at the attestations " +
            "table by UNIQUE(snapshot_id, witness_signing_public_key) " +
            "(HLAM-67); when the POST endpoint lands, this test should " +
            "round-trip two identical attestations and assert the second " +
            "surfaces as PKENetworkError.duplicate."
        )
    }

    // MARK: AC #2 — negative path: hash mismatch (deferred)

    func test_blobHashMismatch_surfacesAsHashMismatch() async throws {
        try await requireBackendReachable()
        throw XCTSkip(
            "Blocked on PUT /v1/snapshots/{id}/blob (HLAM-139) and the " +
            "matching iOS client method (HLAM-151). The hash-mismatch " +
            "check fires when the uploaded blob's SHA-256 does not match " +
            "the commitment's ciphertext_hash; the server responds with " +
            "error.code='hash_mismatch' which maps to " +
            "PKENetworkError.hashMismatch."
        )
    }
}
#endif
