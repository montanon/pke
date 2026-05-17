// ECDSA P-256 sign / verify with strict raw-P1363 (64-byte) wire format.
// Mirrors the backend `pke_backend.crypto.signatures` contract from HLAM-16 and
// the canonical-encoding rule pinned in HLAM-3 / HLAM-25.

import Crypto
import Foundation

public enum Signatures {

    /// Sign `payload` with the supplied P-256 private key.
    /// Returns exactly 64 bytes (raw P1363 — `r || s`, each big-endian, left-padded to 32).
    /// Empty payload is permitted.
    public static func sign(
        payload: Data,
        with privateKey: P256.Signing.PrivateKey
    ) throws -> Data {
        do {
            let signature = try privateKey.signature(for: payload)
            return signature.rawRepresentation
        } catch {
            throw CryptoError.signatureFormat(reason: "sign failed")
        }
    }

    /// Verify a 64-byte raw P1363 `signature` over `payload` under `publicKey`.
    ///
    /// Order of checks (deliberate — the length gate runs before any parsing or verify math
    /// so attackers learn nothing about the key or digest from rejection latency):
    ///   1. `signature.count == 64`, else `.signatureFormat`.
    ///   2. parse into `ECDSASignature(rawRepresentation:)`, else `.signatureFormat`.
    ///   3. `publicKey.isValidSignature`, else `.signatureVerification`.
    public static func verify(
        _ signature: Data,
        of payload: Data,
        by publicKey: P256.Signing.PublicKey
    ) throws {
        guard signature.count == 64 else {
            throw CryptoError.signatureFormat(
                reason: "expected 64-byte raw P1363, got \(signature.count) bytes"
            )
        }
        let parsed: P256.Signing.ECDSASignature
        do {
            parsed = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        } catch {
            throw CryptoError.signatureFormat(reason: "rawRepresentation rejected")
        }
        let ok = publicKey.isValidSignature(parsed, for: payload)
        if !ok {
            throw CryptoError.signatureVerification(reason: "verify failed")
        }
    }
}
