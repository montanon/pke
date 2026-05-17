// Typed error surface for `SnapshotDecryptionService` (HLAM-118).
//
// Mirrors `PKECrypto.CryptoError` and the Python backend's
// `pke_backend.crypto.errors` conventions: every payload carries only
// non-sensitive labels (lengths, layout names, taxonomy strings). NEVER
// embed key bytes, plaintext, or full ciphertext into a `reason:` — these
// values flow into logs and verifier reports.
//
// Reason taxonomy (stable across patch releases, callers may pattern-match):
//
//   * "recipient mismatch"     — grant's recipient pub key ≠ this device's
//   * "tag verification failed" — GCM tag mismatch on unwrap (either the
//                                 wrapped blob or the AAD context was
//                                 tampered)
//   * "open failed"             — GCM tag mismatch on snapshot decrypt
//   * any other string is informational — do not pattern-match.

import Foundation

public enum DecryptionError: Error, Equatable, Sendable {
    case unwrapFailed(reason: String)
    case decryptFailed(reason: String)
    case malformedCiphertext(byteCount: Int)
    case unsupportedAlgorithm(String)
}

extension DecryptionError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unwrapFailed(let reason):
            return "unwrapFailed: \(reason)"
        case .decryptFailed(let reason):
            return "decryptFailed: \(reason)"
        case .malformedCiphertext(let byteCount):
            return "malformedCiphertext: byteCount \(byteCount)"
        case .unsupportedAlgorithm(let name):
            return "unsupportedAlgorithm: \(name)"
        }
    }
}
