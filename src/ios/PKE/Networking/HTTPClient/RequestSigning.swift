// HLAM-147 — canonical-encoding integration for the HTTP client.
//
// Thin call site that funnels any `Encodable` request body through HLAM-7's
// `PKECrypto.CanonicalJSON` (via HLAM-10's `toJSONValue()` bridge) and onto
// a `URLRequest` with the correct `Content-Type`. **No new encoder lives
// under `Networking/`** — this file owns the integration, not the byte
// production.
//
// `RequestSigning` is the namespace name pinned by the HLAM-49 design.
// HLAM-148 extends it with the actual signing step (build canonical bytes
// here, sign over them, embed the signature back into the payload, send).

#if canImport(Security)
import Foundation
import PKECrypto
import PKEProtocol

public enum RequestSigning {

    /// Standard PKE JSON content type for canonical-encoded request bodies.
    /// Pinned at this layer so endpoint modules never spell it out by hand.
    public static let canonicalJSONContentType = "application/json; charset=utf-8"

    /// Produces canonical-JSON bytes for `model` by routing through
    /// `Encodable.toJSONValue()` (HLAM-10) and `CanonicalJSON.encode`
    /// (HLAM-7). The output is byte-identical to what the backend computes
    /// for the same value — signature verification depends on this.
    public static func canonicalBytes<T: Encodable>(_ model: T) throws -> Data {
        let jsonValue = try model.toJSONValue()
        return try CanonicalJSON.encode(jsonValue)
    }

    /// Builds a `URLRequest` whose body is the canonical-JSON encoding of
    /// `body` and whose `Content-Type` is `application/json; charset=utf-8`.
    /// Caller picks the HTTP method (`POST` is the only verb the MVP uses
    /// with a body; `PUT` is reserved for blob upload which carries
    /// `application/octet-stream`).
    public static func makeJSONRequest<T: Encodable>(
        url: URL,
        method: String,
        body: T
    ) throws -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue(canonicalJSONContentType, forHTTPHeaderField: "Content-Type")
        request.httpBody = try canonicalBytes(body)
        return request
    }
}
#endif
