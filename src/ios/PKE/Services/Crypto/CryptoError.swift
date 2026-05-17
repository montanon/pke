// Unified crypto error taxonomy mirroring the Python backend's
// `pke_backend.crypto.errors` types. The `reason` payload must NEVER contain
// key bytes, plaintext, or signature material — only offsets, lengths, and
// non-sensitive labels suitable for logs and verifier reports.

import Foundation

public enum CryptoError: Error, Equatable, Sendable {
    case canonicalEncoding(reason: String)
    case encoding(reason: String)
    case signatureFormat(reason: String)
    case signatureVerification
    case hashChain(reason: String)
    case aead(reason: String)
    case wrap(reason: String)
    case keychain(reason: String)
    case identity(reason: String)
}

extension CryptoError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .canonicalEncoding(let reason):
            return "canonicalEncoding: \(reason)"
        case .encoding(let reason):
            return "encoding: \(reason)"
        case .signatureFormat(let reason):
            return "signatureFormat: \(reason)"
        case .signatureVerification:
            return "signatureVerification"
        case .hashChain(let reason):
            return "hashChain: \(reason)"
        case .aead(let reason):
            return "aead: \(reason)"
        case .wrap(let reason):
            return "wrap: \(reason)"
        case .keychain(let reason):
            return "keychain: \(reason)"
        case .identity(let reason):
            return "identity: \(reason)"
        }
    }
}
