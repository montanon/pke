import Foundation

// Reasons MUST reference structural info only (index, length, character class).
// Never include key bytes, plaintext, signature material, or raw input bytes.
public enum CryptoError: Error, Equatable {
    case encoding(reason: String? = nil)
    case canonicalEncoding(reason: String? = nil)
}
