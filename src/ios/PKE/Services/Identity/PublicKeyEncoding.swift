// base64url-no-pad encoding for the two P-256 public-key flavors carried on
// the wire. Both helpers funnel through `PKECrypto.Base64URL.encode` so the
// alphabet and padding policy stay aligned with the rest of the protocol.

#if canImport(Security)
import Crypto
import Foundation
import PKECrypto

public enum PublicKeyEncoding {

    public static func signingPublicKey(_ key: P256.Signing.PublicKey) -> String {
        PKECrypto.Base64URL.encode(key.rawRepresentation)
    }

    public static func encryptionPublicKey(_ key: P256.KeyAgreement.PublicKey) -> String {
        PKECrypto.Base64URL.encode(key.rawRepresentation)
    }
}
#endif
