// Device identity: a pair of P-256 private keys (ECDSA signing + ECDH
// agreement) persisted in the Keychain on first launch and reused thereafter.
//
// `loadOrCreate()` implements the 6-step half-state-recovery algorithm from
// HLAM-8. The algorithm is idempotent: returns existing keys when both are
// present, generates the missing one when exactly one is present, and
// generates both on cold start. Half-state is not fatal — losing a single
// Keychain item (corruption, OS migration, partial wipe) recovers cleanly
// instead of bricking identity.
//
// No key bytes are logged — even in debug. Tests validate via fake state, not
// by inspecting stdout.

#if canImport(Security)
import Crypto
import Foundation
import PKECrypto

public struct DeviceIdentity: Sendable {
    public let signingKey: P256.Signing.PrivateKey
    public let agreementKey: P256.KeyAgreement.PrivateKey

    public init(
        signingKey: P256.Signing.PrivateKey,
        agreementKey: P256.KeyAgreement.PrivateKey
    ) {
        self.signingKey = signingKey
        self.agreementKey = agreementKey
    }
}

public struct DeviceIdentityService {
    private let keychain: KeychainProtocol

    public init(keychain: KeychainProtocol = Keychain()) {
        self.keychain = keychain
    }

    public func loadOrCreate() throws -> DeviceIdentity {
        let signingBytes = try keychain.get(label: IdentityLabels.signingTag)
        let agreementBytes = try keychain.get(label: IdentityLabels.agreementTag)

        switch (signingBytes, agreementBytes) {
        case let (.some(sBytes), .some(aBytes)):
            let signing = try Self.parseSigning(sBytes)
            let agreement = try Self.parseAgreement(aBytes)
            return DeviceIdentity(signingKey: signing, agreementKey: agreement)
        case (.none, .none):
            return try generateBothAndPersist()
        case let (.some(sBytes), .none):
            let signing = try Self.parseSigning(sBytes)
            let agreement = P256.KeyAgreement.PrivateKey()
            try keychain.set(label: IdentityLabels.agreementTag, data: agreement.rawRepresentation)
            return DeviceIdentity(signingKey: signing, agreementKey: agreement)
        case let (.none, .some(aBytes)):
            let agreement = try Self.parseAgreement(aBytes)
            let signing = P256.Signing.PrivateKey()
            try keychain.set(label: IdentityLabels.signingTag, data: signing.rawRepresentation)
            return DeviceIdentity(signingKey: signing, agreementKey: agreement)
        }
    }

    private func generateBothAndPersist() throws -> DeviceIdentity {
        let signing = P256.Signing.PrivateKey()
        let agreement = P256.KeyAgreement.PrivateKey()
        try keychain.set(label: IdentityLabels.signingTag, data: signing.rawRepresentation)
        do {
            try keychain.set(label: IdentityLabels.agreementTag, data: agreement.rawRepresentation)
        } catch {
            // Best-effort rollback of the signing write so a second call sees
            // a clean Keychain rather than a half-state. Cleanup failures are
            // intentionally swallowed: the original write error is what the
            // caller needs to act on.
            try? keychain.delete(label: IdentityLabels.signingTag)
            throw error
        }
        return DeviceIdentity(signingKey: signing, agreementKey: agreement)
    }

    private static func parseSigning(_ bytes: Data) throws -> P256.Signing.PrivateKey {
        do {
            return try P256.Signing.PrivateKey(rawRepresentation: bytes)
        } catch {
            throw CryptoError.identity(reason: "keychain returned malformed key bytes")
        }
    }

    private static func parseAgreement(_ bytes: Data) throws -> P256.KeyAgreement.PrivateKey {
        do {
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes)
        } catch {
            throw CryptoError.identity(reason: "keychain returned malformed key bytes")
        }
    }
}
#endif
