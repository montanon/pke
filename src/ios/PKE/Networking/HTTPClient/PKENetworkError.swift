// HLAM-149 / HLAM-154 (subset) — error taxonomy for the iOS HTTP client.
//
// Scoped to the cases the response-verification pipeline raises today.
// HLAM-154 rounds out the full networking error surface (transport,
// HTTP, decode, server-error envelope, etc.); for now we only define
// `verificationFailed(CryptoError)` since HLAM-149 needs it. Adding the
// type here (vs. inlining in `ResponseVerification`) gives later stories
// a stable target to extend.

#if canImport(Security)
import Foundation
import PKECrypto

/// Errors surfaced by the PKE HTTP client.
///
/// Only `verificationFailed` ships in HLAM-149; HLAM-154 extends this
/// taxonomy with transport, HTTP, decoding, and server-error cases. The
/// enum is non-frozen so future cases stay additive.
public enum PKENetworkError: Error, Equatable, Sendable {

    /// Signature re-verification on an inner protocol payload failed. The
    /// wrapped `CryptoError` carries the underlying reason
    /// (`.signatureFormat`, `.signatureVerification`,
    /// `.canonicalEncoding`).
    case verificationFailed(CryptoError)
}
#endif
