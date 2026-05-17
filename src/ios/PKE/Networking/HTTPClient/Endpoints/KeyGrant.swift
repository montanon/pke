// HLAM-153 — key-grant endpoints for the iOS HTTP client.
//
// Three methods are layered onto `PKEHTTPClient` as a public extension:
//
//   * `createKeyGrant(_:)` — POST `/v1/snapshots/{snapshot_id}/key-grants`.
//     The request body is produced by `RequestSigning.sign(_:with:)` so the
//     wire bytes are the canonical, signed form. On success the response is
//     decoded back into a `KeyGrant` and re-verified through
//     `ResponseVerification.verify(_:)` — the server may have normalised
//     timestamps or populated a `grant_id`, and any mutation that breaks the
//     signature must surface locally as `PKENetworkError.verificationFailed`.
//
//   * `listKeyGrants(snapshotId:)` — GET the same collection URL. The
//     response envelope is `{"key_grants": [KeyGrant, ...]}` (the wrapper
//     key is our best guess at the backend shape; HLAM-47 will pin it). Each
//     grant in the list is re-verified via
//     `ResponseVerification.verifyAll(_:)` — a single tampered grant fails
//     the whole call.
//
//   * `fetchKeyGrant(_:)` — GET `/v1/key-grants/{grant_id}`. Grant ids are
//     the bearer-capability in the MVP (no separate auth header), so the
//     URL is the full credential. The fetched grant is re-verified.
//
// Backend failures arrive in the uniform `{"error": {"code": ..., "detail":
// ...}}` envelope and route through `PKENetworkError.from(backendError:)`.
// 409 `duplicate` and 422 `signature_invalid` are the two failure modes
// the create endpoint can return that aren't generic.
//
// Integration tests against `make serve` are deferred until HLAM-47 lands
// the backend route; the tests in this story are URL-protocol-mocked.

#if canImport(Security)
import Foundation
import PKECrypto
import PKEIdentity
import PKEProtocol

public extension PKEHTTPClient {

    /// POST a signed `KeyGrant` to
    /// `/v1/snapshots/{snapshot_id}/key-grants`. The body is the full
    /// canonical-JSON signed form produced by `RequestSigning.sign`. The
    /// server's response (which may have populated a `grant_id` or
    /// normalised the timestamp) is decoded and re-verified end-to-end
    /// before being returned.
    func createKeyGrant(_ grant: KeyGrant) async throws -> KeyGrant {
        let url = baseURL.appendingPathComponent(
            "v1/snapshots/\(grant.snapshotId)/key-grants"
        )
        let body: Data
        do {
            body = try RequestSigning.sign(grant, with: deviceIdentity)
        } catch let cryptoError as CryptoError {
            throw PKENetworkError.encoding(reason: "\(cryptoError)")
        } catch {
            throw PKENetworkError.encoding(reason: "\(error)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(
            RequestSigning.canonicalJSONContentType,
            forHTTPHeaderField: "Content-Type"
        )
        request.httpBody = body

        let (data, response) = try await send(request)
        let parsed: KeyGrant = try Self.decodeOrThrow(data: data, response: response)
        try ResponseVerification.verify(parsed)
        return parsed
    }

    /// GET `/v1/snapshots/{snapshot_id}/key-grants` and decode the response
    /// envelope `{"key_grants": [KeyGrant, ...]}`. Each grant is re-verified
    /// through `ResponseVerification.verifyAll` — a single tampered grant
    /// fails the whole call.
    func listKeyGrants(snapshotId: String) async throws -> [KeyGrant] {
        let url = baseURL.appendingPathComponent(
            "v1/snapshots/\(snapshotId)/key-grants"
        )
        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        let (data, response) = try await send(request)
        let envelope: KeyGrantListResponse = try Self.decodeOrThrow(
            data: data,
            response: response
        )
        try ResponseVerification.verifyAll(envelope.keyGrants.map { $0 as any SignablePayload })
        return envelope.keyGrants
    }

    /// GET `/v1/key-grants/{grant_id}`. The grant id itself is the
    /// bearer-capability in the MVP — no separate auth header is sent. The
    /// returned grant is re-verified inline.
    func fetchKeyGrant(_ grantId: String) async throws -> KeyGrant {
        let url = baseURL.appendingPathComponent("v1/key-grants/\(grantId)")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        let (data, response) = try await send(request)
        let parsed: KeyGrant = try Self.decodeOrThrow(data: data, response: response)
        try ResponseVerification.verify(parsed)
        return parsed
    }

    // MARK: - Response parsing

    /// Decode `data` as `T` when `response` carries a 2xx status, otherwise
    /// parse the body as a `BackendErrorEnvelope` and rethrow as the matching
    /// `PKENetworkError` case. This helper lives in the key-grant module on
    /// purpose: HLAM-155 will extract a shared variant once two endpoint
    /// stories have landed and the duplication is visible.
    private static func decodeOrThrow<T: Decodable>(
        data: Data,
        response: HTTPURLResponse
    ) throws -> T {
        if (200..<300).contains(response.statusCode) {
            do {
                return try JSONDecoder().decode(T.self, from: data)
            } catch {
                throw PKENetworkError.decoding(reason: "\(error)")
            }
        }
        let envelope: BackendErrorEnvelope
        do {
            envelope = try JSONDecoder().decode(BackendErrorEnvelope.self, from: data)
        } catch {
            throw PKENetworkError.internalServerError
        }
        throw PKENetworkError.from(backendError: envelope)
    }
}

/// Wire shape of the list-key-grants response. The wrapper key
/// (`key_grants`) is the iOS client's expectation; HLAM-47 will pin the
/// backend side. This type is intentionally private — endpoint modules
/// own their own envelopes and never leak them across module boundaries.
private struct KeyGrantListResponse: Decodable {

    let keyGrants: [KeyGrant]

    enum CodingKeys: String, CodingKey {
        case keyGrants = "key_grants"
    }
}
#endif
