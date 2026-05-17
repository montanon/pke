// HLAM-150 — Identity endpoints (HTTP client).
//
// Three calls on `PKEHTTPClient` exposed as a public extension:
//
//   * `registerIdentity(signingKey:encryptionKey:displayName:)` —
//     POST /v1/identities. The body is canonical-JSON encoded by way of
//     `RequestSigning.makeJSONRequest`. Registration is the one outbound
//     payload that is *not* ECDSA-signed: the device has no server-assigned
//     identity yet, so the request stands on TLS + bootstrap policy alone.
//
//   * `fetchIdentity(_:)` — GET /v1/identities/{id}.
//
//   * `fetchIdentityBySigningKey(_:)` — GET /v1/identities/by-signing-key/{key}.
//     `{key}` is the base64url (URL-safe alphabet, unpadded) encoding of the
//     32/64-byte raw `P256.Signing.PublicKey` bytes; no percent-encoding is
//     required, and the call site routes through `PKECrypto.Base64URL.encode`
//     so the alphabet stays in lock-step with every other base64url field on
//     the wire.
//
// All three call sites share a small `parseResponse` helper that decodes the
// `BackendErrorEnvelope` for non-2xx responses and routes through
// `PKENetworkError.from(backendError:)` so the typed error surface in
// HLAM-154 stays uniform. Status codes that fail to carry a recognisable
// envelope fall back to a status-class default (`.notFound`, `.duplicate`,
// `.malformedPayload`, `.internalServerError`). `URLError` thrown by the
// underlying `send(_:)` wraps as `.transport(error.code)`.
//
// Integration tests against `make serve` are out of scope here — the live
// backend endpoints land under HLAM-47. This story covers the iOS surface
// only, with unit-level mocks via `MockURLProtocol`.

#if canImport(Security)
import enum Crypto.P256
import Foundation
import PKECrypto
import PKEIdentity
import PKEProtocol

// MARK: - Public response type

/// Server-side identity record returned by `/v1/identities` endpoints.
///
/// Wire shape (snake_case JSON):
/// ```
/// {
///   "id": "...",
///   "signing_public_key": "<base64url 64 bytes>",
///   "encryption_public_key": "<base64url 64 bytes>",
///   "display_name": "...",          // optional
///   "created_at": "YYYY-MM-DDTHH:MM:SSZ"
/// }
/// ```
public struct Identity: Codable, Equatable, Sendable {

    public let id: String
    public let signingPublicKey: Data
    public let encryptionPublicKey: Data
    public let displayName: String?
    public let createdAt: ISO8601UTCDate

    public init(
        id: String,
        signingPublicKey: Data,
        encryptionPublicKey: Data,
        displayName: String?,
        createdAt: ISO8601UTCDate
    ) {
        self.id = id
        self.signingPublicKey = signingPublicKey
        self.encryptionPublicKey = encryptionPublicKey
        self.displayName = displayName
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case signingPublicKey = "signing_public_key"
        case encryptionPublicKey = "encryption_public_key"
        case displayName = "display_name"
        case createdAt = "created_at"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(String.self, forKey: .id)
        let signingWrapped = try container.decode(Base64UrlData.self, forKey: .signingPublicKey)
        self.signingPublicKey = signingWrapped.wrappedValue
        let encryptionWrapped = try container.decode(Base64UrlData.self, forKey: .encryptionPublicKey)
        self.encryptionPublicKey = encryptionWrapped.wrappedValue
        self.displayName = try container.decodeIfPresent(String.self, forKey: .displayName)
        self.createdAt = try container.decode(ISO8601UTCDate.self, forKey: .createdAt)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(Base64UrlData(wrappedValue: signingPublicKey), forKey: .signingPublicKey)
        try container.encode(
            Base64UrlData(wrappedValue: encryptionPublicKey),
            forKey: .encryptionPublicKey
        )
        try container.encodeIfPresent(displayName, forKey: .displayName)
        try container.encode(createdAt, forKey: .createdAt)
    }
}

// MARK: - Request body

/// Outbound shape for `POST /v1/identities`. Internal — endpoint callers
/// pass typed `P256` public keys; this struct exists only to drive
/// canonical-JSON encoding through `RequestSigning.makeJSONRequest`.
private struct RegisterIdentityRequest: Encodable {

    let signingPublicKey: Data
    let encryptionPublicKey: Data
    let displayName: String?

    enum CodingKeys: String, CodingKey {
        case signingPublicKey = "signing_public_key"
        case encryptionPublicKey = "encryption_public_key"
        case displayName = "display_name"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Base64UrlData(wrappedValue: signingPublicKey), forKey: .signingPublicKey)
        try container.encode(
            Base64UrlData(wrappedValue: encryptionPublicKey),
            forKey: .encryptionPublicKey
        )
        try container.encodeIfPresent(displayName, forKey: .displayName)
    }
}

// MARK: - PKEHTTPClient extension

public extension PKEHTTPClient {

    /// Register this device's identity with the backend.
    ///
    /// Sends the raw 64-byte representations of the supplied P-256 public
    /// keys (signing + key-agreement) plus an optional display name. The
    /// request body is canonical-JSON encoded; registration carries no
    /// ECDSA signature because the device has no server-assigned identity
    /// to bind one to yet.
    func registerIdentity(
        signingKey: P256.Signing.PublicKey,
        encryptionKey: P256.KeyAgreement.PublicKey,
        displayName: String?
    ) async throws -> Identity {
        let url = baseURL.appendingPathComponent("v1/identities")
        let body = RegisterIdentityRequest(
            signingPublicKey: signingKey.rawRepresentation,
            encryptionPublicKey: encryptionKey.rawRepresentation,
            displayName: displayName
        )

        let request: URLRequest
        do {
            request = try RequestSigning.makeJSONRequest(url: url, method: "POST", body: body)
        } catch let cryptoError as CryptoError {
            throw PKENetworkError.encoding(reason: cryptoError.description)
        } catch {
            throw PKENetworkError.encoding(reason: "\(error)")
        }

        return try await performAndDecode(request)
    }

    /// Fetch an identity by its server-assigned id.
    func fetchIdentity(_ id: String) async throws -> Identity {
        let url = baseURL.appendingPathComponent("v1/identities/\(id)")
        let request = URLRequest(url: url)
        return try await performAndDecode(request)
    }

    /// Fetch an identity by its raw signing public-key bytes. The key is
    /// base64url-encoded (URL-safe alphabet, unpadded) so the resulting
    /// string is safe to interpolate directly into the path without
    /// percent-encoding.
    func fetchIdentityBySigningKey(_ key: Data) async throws -> Identity {
        let encoded = PKECrypto.Base64URL.encode(key)
        let url = baseURL.appendingPathComponent("v1/identities/by-signing-key/\(encoded)")
        let request = URLRequest(url: url)
        return try await performAndDecode(request)
    }

    // MARK: - Internal helpers

    /// Issue `request`, then route the response through `parseResponse`.
    /// Translates `URLError` from the transport into `.transport(code:)`.
    private func performAndDecode<T: Decodable>(_ request: URLRequest) async throws -> T {
        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await send(request)
        } catch let urlError as URLError {
            throw PKENetworkError.transport(urlError.code)
        }
        return try Self.parseResponse(data, response)
    }

    /// Decode a 2xx response body as `T`, or map a non-2xx response to a
    /// typed `PKENetworkError`. The backend error envelope is preferred
    /// when present so the typed `code` flows through
    /// `PKENetworkError.from(backendError:)` unchanged; status-class
    /// fallbacks cover responses that ship without a recognisable envelope.
    private static func parseResponse<T: Decodable>(
        _ data: Data,
        _ response: HTTPURLResponse
    ) throws -> T {
        let status = response.statusCode
        if (200..<300).contains(status) {
            do {
                return try JSONDecoder().decode(T.self, from: data)
            } catch {
                throw PKENetworkError.decoding(reason: "\(error)")
            }
        }

        if let envelope = try? JSONDecoder().decode(BackendErrorEnvelope.self, from: data) {
            throw PKENetworkError.from(backendError: envelope)
        }

        switch status {
        case 400, 422:
            throw PKENetworkError.malformedPayload(detail: "")
        case 404:
            throw PKENetworkError.notFound
        case 409:
            throw PKENetworkError.duplicate(detail: "")
        case 500...599:
            throw PKENetworkError.internalServerError
        default:
            throw PKENetworkError.internalServerError
        }
    }
}
#endif
