// End-to-end snapshot-key wrap for the PKE v0.1 `ecdhp256+aesgcm256`
// construction. The byte layout is pinned by HLAM-3 /
// `context/16_canonical_encoding.md` §HKDF-SHA256:
//
//   shared_secret = ECDH(P-256)  → 32-byte X coordinate (raw)
//   salt          = b"pke/v0.1/keywrap/salt"
//   info          = b"pke/v0.1/keywrap/info"
//                ‖ u16be(len(snapshot_id_utf8)) ‖ snapshot_id_utf8
//                ‖ u16be(len(recipient_pub_raw)) ‖ recipient_pub_raw  (65 bytes, 0x04‖X‖Y)
//   aad           = b"pke/v0.1/keywrap/aad"
//                ‖ u16be(len(snapshot_id_utf8)) ‖ snapshot_id_utf8
//   wrapping_key  = HKDF-SHA256(shared_secret, salt, info, 32)
//   wrapped       = nonce(12) ‖ AES-256-GCM_encrypt(snapshot_key, wrapping_key, nonce, aad)
//                 = nonce(12) ‖ ciphertext(32) ‖ tag(16)  → 60 bytes total
//
// Any future protocol bump MUST mint a new function alongside this one and a
// new `wrapping_algorithm` identifier; the v0.1 constants and layout are never
// mutated in place. Error reasons reference offsets, lengths, and non-secret
// labels only — never key bytes or plaintext.

import Crypto
import Foundation

public enum KeyWrap {

    // Wire-format constant. Callers may use this when sizing buffers.
    public static let wrappedByteCount = 60

    // Locked v0.1 labels.
    static let saltBytes = Data("pke/v0.1/keywrap/salt".utf8)
    static let infoPrefix = Data("pke/v0.1/keywrap/info".utf8)
    static let aadPrefix = Data("pke/v0.1/keywrap/aad".utf8)

    // Wire-format slice offsets for an unwrapped 60-byte blob.
    private static let nonceRange = 0..<12
    private static let ciphertextRange = 12..<44
    private static let tagRange = 44..<60

    // MARK: - Public API

    /// Wrap `snapshotKey` for `recipientPublic` under the owner's identity,
    /// returning 60 bytes laid out as `nonce ‖ ciphertext ‖ tag`. The nonce is
    /// freshly generated from the platform CSPRNG on every call.
    public static func wrap(
        snapshotKey: SymmetricKey,
        ownerPrivate: P256.KeyAgreement.PrivateKey,
        recipientPublic: AgreementPublicKey,
        snapshotId: String
    ) throws -> Data {
        try wrapWithFixedNonce(
            snapshotKey: snapshotKey,
            ownerPrivate: ownerPrivate,
            recipientPublic: recipientPublic,
            snapshotId: snapshotId,
            nonce: AES.GCM.Nonce()
        )
    }

    /// Unwrap a 60-byte `wrapped` blob from `ownerPublic` to recover the
    /// snapshot key. Any failure (length, tag mismatch, AAD mismatch, point
    /// rejection) surfaces as `CryptoError.aead`. The length gate runs before
    /// any crypto so obviously malformed inputs reject in constant work.
    public static func unwrap(
        _ wrapped: Data,
        recipientPrivate: P256.KeyAgreement.PrivateKey,
        ownerPublic: AgreementPublicKey,
        snapshotId: String
    ) throws -> SymmetricKey {
        guard wrapped.count == wrappedByteCount else {
            throw CryptoError.aead(
                reason: "expected \(wrappedByteCount) bytes, got \(wrapped.count)"
            )
        }
        let nonceData = wrapped.subdata(in: offsetRange(nonceRange, in: wrapped))
        let ctData = wrapped.subdata(in: offsetRange(ciphertextRange, in: wrapped))
        let tagData = wrapped.subdata(in: offsetRange(tagRange, in: wrapped))

        let sharedBytes = try sharedSecretBytes(
            localPrivate: recipientPrivate,
            peerPublic: ownerPublic.underlying
        )
        // `info` is built with the RECIPIENT's pub in both directions; here the
        // recipient is "us", so derive it from our own private key.
        let recipientPubRaw = recipientPrivate.publicKey.x963Representation
        let wrappingKey = try deriveWrappingKey(
            sharedSecret: sharedBytes,
            snapshotId: snapshotId,
            recipientPubRaw: Data(recipientPubRaw)
        )
        let aad = try buildAad(snapshotId: snapshotId)

        let box: AES.GCM.SealedBox
        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ctData, tag: tagData)
        } catch {
            throw CryptoError.aead(reason: "wrapped layout rejected by AEAD")
        }
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(box, using: wrappingKey, authenticating: aad)
        } catch {
            throw CryptoError.aead(reason: "tag verification failed")
        }
        return SymmetricKey(data: plaintext)
    }

    // MARK: - package-visible internals (callable from @testable tests)

    /// Deterministic-nonce variant of `wrap`. The public API never exposes this
    /// surface; it exists so vector tests can pin the nonce supplied by the
    /// fixture and assert byte-for-byte parity against the Python primitive.
    static func wrapWithFixedNonce(
        snapshotKey: SymmetricKey,
        ownerPrivate: P256.KeyAgreement.PrivateKey,
        recipientPublic: AgreementPublicKey,
        snapshotId: String,
        nonce: AES.GCM.Nonce
    ) throws -> Data {
        let sharedBytes = try sharedSecretBytes(
            localPrivate: ownerPrivate,
            peerPublic: recipientPublic.underlying
        )
        let recipientPubRaw = Data(recipientPublic.underlying.x963Representation)
        let wrappingKey = try deriveWrappingKey(
            sharedSecret: sharedBytes,
            snapshotId: snapshotId,
            recipientPubRaw: recipientPubRaw
        )
        let aad = try buildAad(snapshotId: snapshotId)
        let snapshotBytes = snapshotKey.withUnsafeBytes { Data($0) }
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(
                snapshotBytes,
                using: wrappingKey,
                nonce: nonce,
                authenticating: aad
            )
        } catch {
            throw CryptoError.aead(reason: "AEAD seal failed")
        }
        var out = Data(capacity: wrappedByteCount)
        out.append(contentsOf: Data(nonce))
        out.append(sealed.ciphertext)
        out.append(sealed.tag)
        return out
    }

    static func sharedSecretBytes(
        localPrivate: P256.KeyAgreement.PrivateKey,
        peerPublic: P256.KeyAgreement.PublicKey
    ) throws -> Data {
        // `sharedSecretFromKeyAgreement` only throws on point validation,
        // which CryptoKit performs on key construction — by the time we hold
        // typed keys this call is total. We still surface a typed `.aead`
        // instead of crashing so adversarial input on a future code path
        // cannot turn into a DoS.
        let shared: SharedSecret
        do {
            shared = try localPrivate.sharedSecretFromKeyAgreement(with: peerPublic)
        } catch {
            throw CryptoError.aead(reason: "ecdh failed")
        }
        return shared.withUnsafeBytes { Data($0) }
    }

    static func deriveWrappingKey(
        sharedSecret: Data,
        snapshotId: String,
        recipientPubRaw: Data
    ) throws -> SymmetricKey {
        let info = try buildHkdfInfo(snapshotId: snapshotId, recipientPubRaw: recipientPubRaw)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: saltBytes,
            info: info,
            outputByteCount: 32
        )
    }

    static func buildHkdfInfo(snapshotId: String, recipientPubRaw: Data) throws -> Data {
        let snapshotIdBytes = Data(snapshotId.utf8)
        var out = Data(capacity: infoPrefix.count + 2 + snapshotIdBytes.count + 2 + recipientPubRaw.count)
        out.append(infoPrefix)
        out.append(try u16be(snapshotIdBytes.count))
        out.append(snapshotIdBytes)
        out.append(try u16be(recipientPubRaw.count))
        out.append(recipientPubRaw)
        return out
    }

    static func buildAad(snapshotId: String) throws -> Data {
        let snapshotIdBytes = Data(snapshotId.utf8)
        var out = Data(capacity: aadPrefix.count + 2 + snapshotIdBytes.count)
        out.append(aadPrefix)
        out.append(try u16be(snapshotIdBytes.count))
        out.append(snapshotIdBytes)
        return out
    }

    static func u16be(_ value: Int) throws -> Data {
        guard value >= 0 && value <= 0xFFFF else {
            throw CryptoError.wrap(reason: "length \(value) does not fit u16be")
        }
        return Data([UInt8(value >> 8), UInt8(value & 0xFF)])
    }

    // MARK: - Helpers

    private static func offsetRange(_ range: Range<Int>, in data: Data) -> Range<Int> {
        let base = data.startIndex
        return (base + range.lowerBound)..<(base + range.upperBound)
    }
}
