// HKDF-SHA256 derivation wrapper for PKECrypto.
// Mirrors the Python `pke_backend.crypto.kdf.hkdf_sha256` surface and pins
// the RFC 5869 output-length cap (255 * HashLen = 8160 bytes for SHA-256).

import Crypto
import Foundation

public enum KDF {

    /// SHA-256 output length, in bytes.
    public static let hashByteCount = 32

    /// RFC 5869 cap on HKDF output: `255 * HashLen` bytes.
    public static let maxOutputByteCount = 255 * hashByteCount

    /// Derive `length` bytes from `secret` via HKDF-SHA256 (RFC 5869).
    ///
    /// `salt` and `info` may be empty. `length` must satisfy
    /// `1 <= length <= maxOutputByteCount`, otherwise `CryptoError.encoding`
    /// is thrown (the project's canonical input-bounds variant — there is
    /// no dedicated kdf case in `CryptoError`).
    public static func hkdfSHA256(
        secret: Data,
        salt: Data,
        info: Data,
        length: Int
    ) throws -> SymmetricKey {
        guard length >= 1, length <= Self.maxOutputByteCount else {
            throw CryptoError.encoding(
                reason: "hkdf length \(length) out of range [1, \(Self.maxOutputByteCount)]"
            )
        }
        let ikm = SymmetricKey(data: secret)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: length
        )
    }
}
