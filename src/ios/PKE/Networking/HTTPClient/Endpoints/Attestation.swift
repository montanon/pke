// HLAM-152 — attestation batch upload endpoint for the HTTP client.
//
// Single method on `PKEHTTPClient` (as a `public extension`) that POSTs a
// batch of already-signed `WitnessAttestation` payloads to
// `/v1/snapshots/{snapshot_id}/attestations`. Each attestation carries the
// witness's signature from capture time (HLAM-148) so the batch itself is
// *not* re-signed — the request body is a plain canonical-JSON object
// `{ "attestations": [...] }`. Wrapping the array in an object keeps the
// schema forward-compatible.
//
// Pre-flight rejects empty batches and batches whose size exceeds the 50-
// item cap with `PKENetworkError.malformedPayload` *before* contacting the
// server. The cap protects the backend's per-request budget; the empty-
// batch guard protects against accidental no-op POSTs that would otherwise
// be silently accepted by the server.
//
// Successful responses (HTTP 200-299 inclusive — the server may use 207
// "Multi-Status" for partial-success batches, but some deployments emit
// 200 with the same body shape, so we treat the whole 2xx range
// uniformly) decode into `AttestationUploadResult`, which splits the
// response into `accepted` (session-nonce strings) and `rejected`
// (`(session_nonce, reason)` pairs). Partial successes never throw.
//
// Hard rejections from the server (4xx carrying the uniform error
// envelope) route through `PKENetworkError.from(backendError:)`. 404 is a
// special case that maps to `.notFound` regardless of envelope content
// (the snapshot id may have been mistyped). 5xx responses and any 4xx
// response we cannot decode as a backend envelope surface as
// `.uploadFailed(reason:)`. Transport-layer failures surface as
// `.transport(URLError.Code)`.
//
// Integration tests against `make serve` are deferred until HLAM-47 lands
// the backend endpoint; unit tests in `AttestationEndpointsTests` cover
// the canonical body shape, the pre-flight guards, partial-success
// parsing, the hard-rejection envelope mapping, and the transport-error
// path with `MockURLProtocol`.

#if canImport(Security)
import Foundation
import PKECrypto
import PKEIdentity
import PKEProtocol

/// Result returned by `PKEHTTPClient.uploadAttestations(_:_:)`. Partial
/// successes are represented as a non-empty `rejected` list alongside
/// `accepted`; the call never throws when the server returns a 2xx with a
/// decodable body.
public struct AttestationUploadResult: Codable, Equatable, Sendable {

    /// `session_nonce` (base64url) of every attestation the server
    /// committed to the ledger.
    public let accepted: [String]

    /// Per-attestation rejections from a partial-success response. Empty
    /// when every attestation was accepted.
    public let rejected: [RejectedAttestation]

    public init(accepted: [String], rejected: [RejectedAttestation]) {
        self.accepted = accepted
        self.rejected = rejected
    }

    public struct RejectedAttestation: Codable, Equatable, Sendable {

        /// Base64url-encoded session nonce of the rejected attestation.
        public let sessionNonce: String

        /// Server-supplied human-readable reason (e.g.
        /// "session_nonce already committed").
        public let reason: String

        public init(sessionNonce: String, reason: String) {
            self.sessionNonce = sessionNonce
            self.reason = reason
        }

        enum CodingKeys: String, CodingKey {
            case sessionNonce = "session_nonce"
            case reason
        }
    }
}

public extension PKEHTTPClient {

    /// Maximum number of `WitnessAttestation` payloads accepted per POST.
    /// The cap is pinned at this layer so callers cannot accidentally
    /// overflow the backend's per-request budget.
    static var attestationBatchCap: Int { 50 }

    /// Upload a batch of already-signed `WitnessAttestation`s for
    /// `snapshotId`. The capturer's signature inside each attestation is
    /// preserved verbatim — the batch wrapper is *not* re-signed.
    ///
    /// Pre-flight:
    /// * empty batches throw `.malformedPayload`,
    /// * batches larger than `attestationBatchCap` throw `.malformedPayload`,
    ///
    /// without contacting the server in either case.
    ///
    /// Response handling:
    /// * 200-299 → decode `AttestationUploadResult` (partial successes
    ///   surface in `rejected`, never as a thrown error),
    /// * 404 → `.notFound` (snapshot id unknown),
    /// * other 4xx with a uniform error envelope → mapped via
    ///   `PKENetworkError.from(backendError:)`,
    /// * 5xx or any 4xx whose body is not a decodable envelope →
    ///   `.uploadFailed(reason: "HTTP <status>")`,
    /// * transport failure → `.transport(URLError.Code)`.
    func uploadAttestations(
        _ snapshotId: String,
        _ attestations: [WitnessAttestation]
    ) async throws -> AttestationUploadResult {
        try validateBatchSize(attestations)

        let url = baseURL.appendingPathComponent("v1/snapshots/\(snapshotId)/attestations")
        let body = AttestationBatchBody(attestations: attestations)
        let request: URLRequest
        do {
            request = try RequestSigning.makeJSONRequest(url: url, method: "POST", body: body)
        } catch let cryptoError as CryptoError {
            throw PKENetworkError.encoding(reason: "canonical encoding failed: \(cryptoError)")
        } catch {
            throw PKENetworkError.encoding(reason: "canonical encoding failed: \(error)")
        }

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await send(request)
        } catch let urlError as URLError {
            throw PKENetworkError.transport(urlError.code)
        } catch {
            throw PKENetworkError.transport(.unknown)
        }

        return try Self.parseUploadResponse(status: response.statusCode, body: data)
    }

    // MARK: - Helpers

    /// Decode the response body for `uploadAttestations(_:_:)` according
    /// to the status-code rules documented above. Factored out so the
    /// method body stays narrowly transport-shaped.
    private static func parseUploadResponse(
        status: Int,
        body: Data
    ) throws -> AttestationUploadResult {
        if (200..<300).contains(status) {
            do {
                return try JSONDecoder().decode(AttestationUploadResult.self, from: body)
            } catch {
                throw PKENetworkError.uploadFailed(reason: "HTTP \(status)")
            }
        }
        if status == 404 {
            throw PKENetworkError.notFound
        }
        if (400..<500).contains(status) {
            if let envelope = try? JSONDecoder().decode(BackendErrorEnvelope.self, from: body) {
                throw PKENetworkError.from(backendError: envelope)
            }
            throw PKENetworkError.uploadFailed(reason: "HTTP \(status)")
        }
        throw PKENetworkError.uploadFailed(reason: "HTTP \(status)")
    }

    private func validateBatchSize(_ attestations: [WitnessAttestation]) throws {
        if attestations.isEmpty {
            throw PKENetworkError.malformedPayload(
                detail: "attestation batch cannot be empty"
            )
        }
        if attestations.count > Self.attestationBatchCap {
            throw PKENetworkError.malformedPayload(
                detail: "attestation batch exceeds \(Self.attestationBatchCap)-item cap "
                    + "(got \(attestations.count))"
            )
        }
    }
}

/// Wire shape for the batch upload body. Wrapping the array in an object
/// keeps the schema forward-compatible (future versions can grow sibling
/// fields without a breaking change to existing clients).
internal struct AttestationBatchBody: Encodable {

    let attestations: [WitnessAttestation]
}
#endif
