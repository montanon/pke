// Thin @MainActor wrapper around HLAM-2's `DeviceIdentityService` / `PKEIdentity`.
//
// Flow code (`BackendClient`, witness flow, recipient unwrap flow) talks to
// `DeviceIdentitySession` instead of touching Keychain or HLAM-2 primitives
// directly. The wrapper:
//
//   * lazily loads-or-creates the device's signing + agreement keypairs on
//     first instantiation (the underlying `DeviceIdentityService.loadOrCreate`
//     is the HLAM-8 half-state-recovery algorithm — idempotent across launches),
//   * exposes the two public keys as 65-byte uncompressed P-256 raw bytes
//     (`0x04 || X || Y`), the form wire payloads carry per HLAM-3,
//   * provides `sign(_:)` and `unwrap(grant:ownerAgreementPublicKey:)` as the
//     ONLY caller-facing crypto surface — private keys never leave the type.
//
// `shared` is a throwing computed property because Keychain access can fail
// when a device is still locked on first launch. Failures are NOT cached:
// once the device unlocks, a subsequent access succeeds and the result is
// cached for the process lifetime. Tests inject `init(service:)` directly
// and never touch `shared`.
//
// Error mapping for `unwrap`:
//
//   * unsupported `wrappingAlgorithm`        → `UnwrapError.unsupportedAlgorithm`
//   * `recipientEncryptionPublicKey` is not THIS device's encryption pubkey
//                                            → `UnwrapError.recipientMismatch`
//   * `CryptoError.aead` from `KeyWrap.unwrap` → `UnwrapError.aead(reason:)`
//
// HLAM-2's `KeyWrap.unwrap` currently collapses every wire-layout failure
// (length, AEAD tag mismatch, ECDH point rejection) into `CryptoError.aead`,
// so in practice the `.aead` path is the only one that fires. Any other
// `CryptoError` case (the `u16be` overflow guard, future error-taxonomy
// changes to `KeyWrap`) is re-thrown verbatim rather than silently dropped.

#if canImport(Security)
// `swift-crypto` exports a `CryptoError` typealias for `CryptoKitError`,
// which clashes with `PKECrypto.CryptoError` and breaks `catch` pattern
// resolution. Import only the symbols we actually reference (`SymmetricKey`).
import struct Crypto.SymmetricKey
import Foundation
import PKECrypto
import PKEIdentity
import PKEProtocol

/// Wrapping algorithms this session knows how to unwrap. The v0.1 protocol
/// only mints `ecdhp256+aesgcm256`; future protocol versions add a new
/// identifier without mutating this set.
private let supportedWrappingAlgorithms: Set<String> = ["ecdhp256+aesgcm256"]

public enum UnwrapError: Error, Equatable, Sendable {
    case unsupportedAlgorithm(String)
    case recipientMismatch
    case aead(reason: String)
}

@MainActor
public final class DeviceIdentitySession {

    /// Process-wide handle. First access loads or creates the on-device
    /// identity; subsequent accesses return the same instance. Throws if
    /// Keychain access fails (e.g. device locked at first launch); the
    /// failure is NOT cached, so a retry after unlock succeeds.
    ///
    /// Static members on a `@MainActor` class are not automatically isolated,
    /// so `shared` and `_instance` carry explicit `@MainActor` annotations to
    /// keep the cell safe under strict-concurrency.
    @MainActor
    public static var shared: DeviceIdentitySession {
        get throws {
            if let cached = _instance {
                return cached
            }
            let new = try DeviceIdentitySession()
            _instance = new
            return new
        }
    }

    @MainActor
    private static var _instance: DeviceIdentitySession?

    private let identity: DeviceIdentity

    public init(service: DeviceIdentityService = DeviceIdentityService()) throws {
        self.identity = try service.loadOrCreate()
    }

    /// 65-byte uncompressed P-256 raw bytes (`0x04 || X || Y`).
    public var signingPublicKey: Data {
        Data(identity.signingKey.publicKey.x963Representation)
    }

    /// 65-byte uncompressed P-256 raw bytes (`0x04 || X || Y`).
    public var encryptionPublicKey: Data {
        Data(identity.agreementKey.publicKey.x963Representation)
    }

    /// Sign `canonicalBytes` with the device signing key. Returns 64-byte
    /// raw P1363 ECDSA per HLAM-2's `Signatures.sign` contract. The caller
    /// is responsible for canonicalization — the wrapper does not mutate
    /// the payload.
    public func sign(_ canonicalBytes: Data) throws -> Data {
        try Signatures.sign(payload: canonicalBytes, with: identity.signingKey)
    }

    /// ECDH(P-256) + AES-256-GCM unwrap. Validates the grant's algorithm
    /// and recipient before invoking HLAM-2's `KeyWrap.unwrap`. The owner's
    /// agreement public key is supplied separately because `KeyGrant`
    /// carries the owner's *signing* key but not the *agreement* key that
    /// ECDH needs; the caller pulls it from the snapshot commitment.
    public func unwrap(
        grant: KeyGrant,
        ownerAgreementPublicKey: AgreementPublicKey
    ) throws -> SymmetricKey {
        guard supportedWrappingAlgorithms.contains(grant.wrappingAlgorithm) else {
            throw UnwrapError.unsupportedAlgorithm(grant.wrappingAlgorithm)
        }
        // Both sides are `Data` holding the canonical SEC1 uncompressed form
        // (`0x04 || X || Y`); byte equality is the right semantic — matches
        // what off-device verifiers do.
        guard grant.recipientEncryptionPublicKey == encryptionPublicKey else {
            throw UnwrapError.recipientMismatch
        }
        do {
            return try KeyWrap.unwrap(
                grant.wrappedSnapshotKey,
                recipientPrivate: identity.agreementKey,
                ownerPublic: ownerAgreementPublicKey,
                snapshotId: grant.snapshotId
            )
        } catch let CryptoError.aead(reason) {
            throw UnwrapError.aead(reason: reason)
        }
    }
}
#endif
