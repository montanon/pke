// HLAM-154 — error taxonomy for the iOS HTTP client.
//
// All non-success paths through the PKE networking layer surface a typed
// `PKENetworkError`. Cases split into two families:
//
//   * **Backend-originated** — emitted by the FastAPI service inside a
//     uniform `{"error": {"code": ..., "detail": ...}}` envelope. The
//     short snake_case `code` value maps to one of the
//     `BackendErrorCode`-bearing cases via `from(backendError:)`. Unknown
//     codes fall through to `.internalServerError` so unfamiliar future
//     codes never crash the client.
//
//   * **iOS-originated** — emitted before/after the request leaves the
//     device: transport failures, encoding/decoding glitches, local
//     signature re-verification failures.
//
// `PKENetworkError` is also `LocalizedError`, so `error.localizedDescription`
// is suitable for non-developer UI surfaces.

#if canImport(Security)
import Foundation
import PKECrypto

/// Errors surfaced by the PKE HTTP client.
///
/// The enum is intentionally non-frozen — future stories may add cases as
/// the protocol evolves. Switches over `PKENetworkError` should always
/// include a `default` arm.
public enum PKENetworkError: Error, Equatable, Sendable {

    // Backend-originated cases (mapped from `{"error":{"code":...}}`).

    /// 400-class: the request body could not be parsed against the schema
    /// or violated a structural rule the canonical encoder caught.
    case malformedPayload(detail: String)

    /// 404: requested resource (snapshot, identity, key grant) does not
    /// exist or the caller lacks the capability bytes to address it.
    case notFound

    /// 409: a uniqueness invariant was violated (e.g. a witness signed the
    /// same `session_nonce` twice). `detail` carries the server's message.
    case duplicate(detail: String)

    /// 422 / domain-specific: signature on the inbound payload failed
    /// server-side verification (distinct from the local re-verify failure
    /// surfaced by `.verificationFailed`).
    case signatureInvalid

    /// 422: blob ciphertext SHA-256 did not match the commitment hash.
    case hashMismatch

    /// 500-class: server reported an unexpected internal error, or the
    /// response carried an `error.code` value the client does not yet
    /// recognise (future-proofing — unknown codes never crash the client).
    case internalServerError

    // iOS-originated cases.

    /// `URLSession` raised a transport-level failure (offline, TLS, host
    /// not reachable, etc.). Preserves the underlying `URLError.Code`.
    case transport(URLError.Code)

    /// A blob upload failed for a non-transport reason (`PUT` rejected,
    /// short read, etc.). `reason` is a developer-facing string.
    case uploadFailed(reason: String)

    /// Local signature re-verification on an inner protocol payload failed.
    /// Wraps the underlying `CryptoError` to keep the diagnostic precise.
    case verificationFailed(CryptoError)

    /// Client-side canonical-encoding step (or `JSONEncoder` pre-pass) raised.
    case encoding(reason: String)

    /// Client-side JSON decoding of a response payload raised.
    case decoding(reason: String)

    // MARK: - Backend mapping

    /// Build a `PKENetworkError` from a parsed backend error envelope.
    ///
    /// Unknown codes (forward-compatibility) collapse to
    /// `.internalServerError` — the design choice is deliberate: the
    /// client treats anything it cannot classify as an opaque server-side
    /// fault, never as a malformed payload, so retry policies stay correct.
    public static func from(backendError envelope: BackendErrorEnvelope) -> PKENetworkError {
        switch envelope.error.code {
        case "malformed_payload":
            return .malformedPayload(detail: envelope.error.detail ?? "")
        case "not_found":
            return .notFound
        case "duplicate":
            return .duplicate(detail: envelope.error.detail ?? "")
        case "signature_invalid":
            return .signatureInvalid
        case "hash_mismatch":
            return .hashMismatch
        case "internal_server_error":
            return .internalServerError
        default:
            return .internalServerError
        }
    }
}

extension PKENetworkError: LocalizedError {

    public var errorDescription: String? {
        switch self {
        case .malformedPayload(let detail):
            return "The request was malformed.\(detail.isEmpty ? "" : " \(detail)")"
        case .notFound:
            return "Requested resource was not found."
        case .duplicate(let detail):
            return "Duplicate submission rejected.\(detail.isEmpty ? "" : " \(detail)")"
        case .signatureInvalid:
            return "Server rejected the payload signature."
        case .hashMismatch:
            return "Blob hash did not match the snapshot commitment."
        case .internalServerError:
            return "The server reported an internal error."
        case .transport(let code):
            return "Network transport failed (\(code.rawValue))."
        case .uploadFailed(let reason):
            return "Blob upload failed.\(reason.isEmpty ? "" : " \(reason)")"
        case .verificationFailed(let cryptoError):
            return "Signature re-verification failed: \(cryptoError)."
        case .encoding(let reason):
            return "Outbound payload could not be encoded.\(reason.isEmpty ? "" : " \(reason)")"
        case .decoding(let reason):
            return "Inbound payload could not be decoded.\(reason.isEmpty ? "" : " \(reason)")"
        }
    }
}

// MARK: - Backend envelope

/// JSON shape of the FastAPI error response, scoped to what the iOS client
/// needs. Mirrors the backend's uniform error envelope (HLAM-143).
public struct BackendErrorEnvelope: Decodable, Equatable, Sendable {

    public let error: BackendErrorBody

    public init(error: BackendErrorBody) {
        self.error = error
    }
}

public struct BackendErrorBody: Decodable, Equatable, Sendable {

    public let code: String
    public let detail: String?

    public init(code: String, detail: String?) {
        self.code = code
        self.detail = detail
    }
}
#endif
