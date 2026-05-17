// Recipient-side decryption service for the PKE v0.1 protocol (HLAM-118).
//
// Composes two HLAM-2 primitives behind one typed-error surface:
//
//   * `KeyWrap.unwrap` — ECDH(P-256) + HKDF-SHA256 + AES-256-GCM unwrap of
//     the wrapped snapshot key per `ecdhp256+aesgcm256`.
//   * `AEAD.open`     — AES-256-GCM decrypt of the snapshot ciphertext
//     blob with the wire `nonce ‖ ct ‖ tag` layout.
//
// The unwrap step is reached via an injected `UnwrapClosure` so the
// service stays cross-platform: Apple platforms wire
// `DeviceIdentitySession.unwrap` (which validates `wrappingAlgorithm` and
// `recipientEncryptionPublicKey` against the on-device identity); tests
// and Linux callers wire `KeyWrap.unwrap` directly with a synthesised
// recipient private key.
//
// Error mapping (see HLAM-118 plan for the full table):
//
//   * Caller-supplied closure may throw `DecryptionError` directly
//     (e.g. `.unsupportedAlgorithm`, `.unwrapFailed(reason: "recipient
//     mismatch")`) — re-thrown unchanged.
//   * `CryptoError.aead(reason:)` from `KeyWrap.unwrap` / `AEAD.open` is
//     mapped to `.unwrapFailed(reason:)` / `.decryptFailed(reason:)`
//     respectively, preserving the layered taxonomy string.
//   * Any other `Error` is wrapped as `.unwrapFailed` or `.decryptFailed`
//     with `String(describing: error)` as the reason — safe because the
//     underlying types never carry secret bytes.
//
// Snapshot-key lifetime (AC #6):
//
// The service stores nothing — the `SymmetricKey` returned from
// `unwrap(...)` is held only by the caller. Callers MUST decrypt promptly
// and let the value fall out of scope so CryptoKit's automatic key-zeroing
// runs. The service intentionally has no caching, no persistence, and no
// retention.

import struct Crypto.SymmetricKey
import Foundation
import PKECrypto
import PKEProtocol

public final class SnapshotDecryptionService: Sendable {

    public typealias UnwrapClosure =
        @Sendable (KeyGrant, AgreementPublicKey) throws -> SymmetricKey

    private let unwrapClosure: UnwrapClosure

    public init(unwrap: @escaping UnwrapClosure) {
        self.unwrapClosure = unwrap
    }

    /// Recover the 32-byte snapshot key for `grant`. Owner's agreement
    /// public key is supplied separately because `KeyGrant` carries the
    /// owner's signing key but not the agreement key that ECDH needs;
    /// callers pull it from the matching `SnapshotCommitment`.
    public func unwrap(
        grant: KeyGrant,
        ownerAgreementPublicKey: AgreementPublicKey
    ) throws -> SymmetricKey {
        do {
            return try unwrapClosure(grant, ownerAgreementPublicKey)
        } catch let error as DecryptionError {
            throw error
        } catch let CryptoError.aead(reason) {
            throw DecryptionError.unwrapFailed(reason: reason)
        } catch {
            throw DecryptionError.unwrapFailed(reason: String(describing: error))
        }
    }

    /// Decrypt a snapshot ciphertext blob (`nonce ‖ ct ‖ tag`) with the
    /// recovered snapshot key. `aad` is the GCM additional authenticated
    /// data the wire format binds to the blob; in v0.1 the snapshot blob
    /// is AAD-free and callers pass `Data()`. The signature is kept
    /// explicit so a future wire bump that binds `snapshot_id` to the
    /// blob AAD doesn't require an API change.
    public func decrypt(
        snapshotKey: SymmetricKey,
        ciphertext: Data,
        aad: Data
    ) throws -> Data {
        guard ciphertext.count >= AEAD.minimumSealedByteCount else {
            throw DecryptionError.malformedCiphertext(byteCount: ciphertext.count)
        }
        do {
            return try AEAD.open(sealed: ciphertext, key: snapshotKey, aad: aad)
        } catch let CryptoError.aead(reason) {
            throw DecryptionError.decryptFailed(reason: reason)
        } catch {
            throw DecryptionError.decryptFailed(reason: String(describing: error))
        }
    }
}
