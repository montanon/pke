// AES-256-GCM authenticated encryption for PKECrypto.
// Wire layout (locked by HLAM-3): `nonce (12) || ciphertext (n) || tag (16)`.
// Mirrors the backend `pke_backend.crypto.aead` contract; error reasons MUST
// never contain key, plaintext, or full ciphertext bytes — only lengths and
// non-sensitive labels suitable for logs.

import Crypto
import Foundation

public enum AEAD {

    /// AES-256 key length, in bytes.
    public static let keyByteCount = 32

    /// GCM nonce length, in bytes.
    public static let nonceByteCount = 12

    /// GCM authentication tag length, in bytes (128-bit, the CryptoKit default).
    public static let tagByteCount = 16

    /// Minimum length of a well-formed sealed blob: nonce + tag, with zero
    /// ciphertext bytes (empty plaintext seals to exactly 28 bytes).
    public static let minimumSealedByteCount = nonceByteCount + tagByteCount

    /// Seal `plaintext` with AES-256-GCM under `key`, binding `aad` and `nonce`.
    /// Returns `nonce || ciphertext || tag`.
    /// - Throws `CryptoError.aead` on input-length errors or any underlying
    ///   CryptoKit failure. Reasons carry only lengths/labels.
    public static func seal(
        plaintext: Data,
        key: SymmetricKey,
        nonce: Data,
        aad: Data
    ) throws -> Data {
        guard key.bitCount == keyByteCount * 8 else {
            throw CryptoError.aead(
                reason: "key length \(key.bitCount / 8) expected \(keyByteCount)"
            )
        }
        guard nonce.count == nonceByteCount else {
            throw CryptoError.aead(
                reason: "nonce length \(nonce.count) expected \(nonceByteCount)"
            )
        }

        let gcmNonce: AES.GCM.Nonce
        do {
            gcmNonce = try AES.GCM.Nonce(data: nonce)
        } catch {
            throw CryptoError.aead(reason: "nonce construction failed")
        }

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: gcmNonce,
                authenticating: aad
            )
        } catch {
            throw CryptoError.aead(reason: "seal failed")
        }

        guard sealedBox.tag.count == tagByteCount else {
            throw CryptoError.aead(
                reason: "tag length \(sealedBox.tag.count) expected \(tagByteCount)"
            )
        }

        var out = Data(capacity: nonceByteCount + sealedBox.ciphertext.count + tagByteCount)
        out.append(contentsOf: sealedBox.nonce)
        out.append(sealedBox.ciphertext)
        out.append(sealedBox.tag)
        return out
    }

    /// Open a `nonce || ciphertext || tag` blob under `key`, binding `aad`.
    /// - Throws `CryptoError.aead` for any structural problem, wrong key/nonce/AAD,
    ///   or tag mismatch.
    public static func open(
        sealed: Data,
        key: SymmetricKey,
        aad: Data
    ) throws -> Data {
        guard key.bitCount == keyByteCount * 8 else {
            throw CryptoError.aead(
                reason: "key length \(key.bitCount / 8) expected \(keyByteCount)"
            )
        }
        guard sealed.count >= minimumSealedByteCount else {
            throw CryptoError.aead(
                reason: "sealed length \(sealed.count) below minimum \(minimumSealedByteCount)"
            )
        }

        let nonceEnd = sealed.startIndex + nonceByteCount
        let tagStart = sealed.endIndex - tagByteCount
        let nonceBytes = sealed[sealed.startIndex..<nonceEnd]
        let ciphertextBytes = sealed[nonceEnd..<tagStart]
        let tagBytes = sealed[tagStart..<sealed.endIndex]

        let gcmNonce: AES.GCM.Nonce
        do {
            gcmNonce = try AES.GCM.Nonce(data: Data(nonceBytes))
        } catch {
            throw CryptoError.aead(reason: "nonce construction failed")
        }

        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(
                nonce: gcmNonce,
                ciphertext: Data(ciphertextBytes),
                tag: Data(tagBytes)
            )
        } catch {
            throw CryptoError.aead(reason: "sealed box construction failed")
        }

        do {
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw CryptoError.aead(reason: "open failed")
        }
    }
}
