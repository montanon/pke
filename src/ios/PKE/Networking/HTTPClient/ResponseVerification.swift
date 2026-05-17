// HLAM-149 — response-verification pipeline.
//
// Re-verify the ECDSA signature on every signed inner protocol payload
// returned by the backend. The response envelope itself is treated as
// untrusted transport — no envelope-level signature check, only the
// per-payload re-verification under each payload's *inline* signing
// public key. The chain of trust is therefore the device's own knowledge
// of which inline public keys it expects (owner / witness / granter),
// not the envelope shape.
//
// Out of scope here: ledger hash-chain validation. That belongs to the
// Verification Service (HLAM-55) — this story only re-runs `Signatures.verify`
// over canonical-bytes-minus-signature, exactly mirroring the signing path
// in HLAM-148.

#if canImport(Security)
import Crypto
import Foundation
import PKECrypto
import PKEProtocol

public enum ResponseVerification {

    /// Re-verify a single signed inner payload. Throws
    /// `PKENetworkError.verificationFailed` on any mismatch — bad public
    /// key encoding, malformed signature, canonical-encoding failure, or
    /// failed `Signatures.verify` call.
    public static func verify(_ payload: any SignablePayload) throws {
        try verifyOne(payload)
    }

    /// Re-verify every signed inner payload in the supplied collection. The
    /// first failure short-circuits and propagates — partial verification is
    /// never reported as success.
    public static func verifyAll(_ payloads: [any SignablePayload]) throws {
        for payload in payloads {
            try verifyOne(payload)
        }
    }

    // MARK: - Implementation

    private static func verifyOne(_ payload: any SignablePayload) throws {
        let payloadType = type(of: payload)
        let signatureKey = payloadType.signatureFieldKey
        let publicKeyKey = payloadType.signingPublicKeyFieldKey

        let pairs = try objectPairs(of: payload)
        let signature = try extractRawBase64URLBytes(from: pairs, key: signatureKey)
        let publicKeyBytes = try extractRawBase64URLBytes(from: pairs, key: publicKeyKey)
        let publicKey = try parseSigningPublicKey(publicKeyBytes)
        let signedBytes = try canonicalBytesMinusSignature(pairs: pairs, signatureKey: signatureKey)

        do {
            try Signatures.verify(signature, of: signedBytes, by: publicKey)
        } catch let cryptoError as CryptoError {
            throw PKENetworkError.verificationFailed(cryptoError)
        } catch {
            throw PKENetworkError.verificationFailed(.signatureVerification)
        }
    }

    private static func objectPairs(
        of payload: any SignablePayload
    ) throws -> [(String, JSONValue)] {
        let jsonValue: JSONValue
        do {
            jsonValue = try payload.toJSONValue()
        } catch let cryptoError as CryptoError {
            throw PKENetworkError.verificationFailed(cryptoError)
        } catch {
            throw PKENetworkError.verificationFailed(
                .canonicalEncoding(reason: "toJSONValue failed: \(error)")
            )
        }
        guard case .object(let pairs) = jsonValue else {
            throw PKENetworkError.verificationFailed(
                .canonicalEncoding(reason: "signable payload must be a JSON object at the root")
            )
        }
        return pairs
    }

    private static func extractRawBase64URLBytes(
        from pairs: [(String, JSONValue)],
        key: String
    ) throws -> Data {
        guard let entry = pairs.first(where: { $0.0 == key }) else {
            throw PKENetworkError.verificationFailed(
                .signatureFormat(reason: "missing '\(key)' field on signed payload")
            )
        }
        guard case .string(let encoded) = entry.1 else {
            throw PKENetworkError.verificationFailed(
                .signatureFormat(reason: "'\(key)' must be a base64url string")
            )
        }
        do {
            return try PKECrypto.Base64URL.decode(encoded)
        } catch let cryptoError as CryptoError {
            throw PKENetworkError.verificationFailed(cryptoError)
        }
    }

    private static func parseSigningPublicKey(_ bytes: Data) throws -> P256.Signing.PublicKey {
        do {
            return try P256.Signing.PublicKey(rawRepresentation: bytes)
        } catch {
            throw PKENetworkError.verificationFailed(
                .signatureFormat(reason: "inline signing public key rejected")
            )
        }
    }

    private static func canonicalBytesMinusSignature(
        pairs: [(String, JSONValue)],
        signatureKey: String
    ) throws -> Data {
        let strippedPairs = pairs.filter { $0.0 != signatureKey }
        do {
            return try CanonicalJSON.encode(.object(strippedPairs))
        } catch let cryptoError as CryptoError {
            throw PKENetworkError.verificationFailed(cryptoError)
        }
    }
}
#endif
