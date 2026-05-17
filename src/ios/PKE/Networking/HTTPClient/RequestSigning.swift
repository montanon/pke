// HLAM-147 / HLAM-148 — canonical encoding + request-signing pipeline for
// the HTTP client.
//
// Thin call site that funnels any `Encodable` request body through HLAM-7's
// `PKECrypto.CanonicalJSON` (via HLAM-10's `toJSONValue()` bridge) and onto
// a `URLRequest` with the correct `Content-Type`. **No new encoder lives
// under `Networking/`** — this file owns the integration, not the byte
// production.
//
// `RequestSigning.sign(_:with:)` (HLAM-148) sits on top of the same
// canonical pipeline: strip the payload's `*_signature` field, canonicalise
// what remains, ECDSA-P256-sign the bytes with the local `DeviceIdentity`
// (raw P1363, 64 bytes, base64url-encoded), re-embed the signature, and
// return the final canonical bytes. The wire bytes are byte-identical to
// what the backend computes for the same value.

#if canImport(Security)
import Foundation
import PKECrypto
import PKEIdentity
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

    // MARK: - HLAM-148 — request signing

    /// Canonicalise `payload` and sign it with the device's ECDSA P-256
    /// signing key, embedding the resulting signature back into the payload's
    /// `*_signature` field. The returned bytes are the final canonical-JSON
    /// wire form (signed) ready to be the body of a request.
    ///
    /// Algorithm (matches the backend pipeline in HLAM-16):
    /// 1. Convert `payload` to `JSONValue`; require an object at the root.
    /// 2. Drop the entry whose key equals `P.signatureFieldKey`; any prior
    ///    value (placeholder, stale, attacker-supplied) is discarded.
    /// 3. Canonical-encode the stripped object — these are the bytes signed.
    /// 4. ECDSA-P256-sign with `identity.signingKey` (`PKECrypto.Signatures`).
    ///    The output is raw P1363, exactly 64 bytes.
    /// 5. base64url-encode the signature; insert it back under
    ///    `P.signatureFieldKey`.
    /// 6. Canonical-encode the signed object and return it.
    public static func sign<P: SignablePayload>(
        _ payload: P,
        with identity: DeviceIdentity
    ) throws -> Data {
        let jsonValue = try payload.toJSONValue()
        guard case let .object(pairs) = jsonValue else {
            throw CryptoError.canonicalEncoding(
                reason: "signable payload must be a JSON object at the root"
            )
        }
        let signatureKey = P.signatureFieldKey

        let strippedPairs = pairs.filter { $0.0 != signatureKey }
        let bytesToSign = try CanonicalJSON.encode(.object(strippedPairs))

        let signatureBytes = try Signatures.sign(
            payload: bytesToSign,
            with: identity.signingKey
        )
        let signatureString = PKECrypto.Base64URL.encode(signatureBytes)

        var signedPairs = strippedPairs
        signedPairs.append((signatureKey, .string(signatureString)))
        return try CanonicalJSON.encode(.object(signedPairs))
    }
}

// MARK: - SignablePayload protocol + conformances

/// A protocol payload that carries a detached ECDSA signature in a
/// `*_signature` field, signed under the public key carried in
/// `*_signing_public_key`. The static field keys name those canonical
/// (snake_case) JSON keys — each payload type uses its own pair
/// (`owner_signature` + `owner_signing_public_key`,
/// `witness_signature` + `witness_signing_public_key`,
/// `grant_signature` + `granted_by_signing_public_key`).
public protocol SignablePayload: Encodable {
    static var signatureFieldKey: String { get }
    static var signingPublicKeyFieldKey: String { get }
}

extension SnapshotCommitment: SignablePayload {
    public static var signatureFieldKey: String { "owner_signature" }
    public static var signingPublicKeyFieldKey: String { "owner_signing_public_key" }
}

extension WitnessAttestation: SignablePayload {
    public static var signatureFieldKey: String { "witness_signature" }
    public static var signingPublicKeyFieldKey: String { "witness_signing_public_key" }
}

extension KeyGrant: SignablePayload {
    public static var signatureFieldKey: String { "grant_signature" }
    public static var signingPublicKeyFieldKey: String { "granted_by_signing_public_key" }
}
#endif
