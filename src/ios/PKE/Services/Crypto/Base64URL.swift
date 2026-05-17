// base64url (RFC 4648 §5) without padding. Mirrors the backend
// `pke_backend.crypto.encoding` contract: `+` and `/` are rejected, padded
// inputs are rejected, and `length mod 4 == 1` is rejected before any decode.

import Foundation

extension PKECrypto {

    public enum Base64URL {

        /// Encode `data` as base64url without padding.
        public static func encode(_ data: Data) -> String {
            let standard = data.base64EncodedString()
            var out = standard
            out = out.replacingOccurrences(of: "+", with: "-")
            out = out.replacingOccurrences(of: "/", with: "_")
            while out.hasSuffix("=") {
                out.removeLast()
            }
            return out
        }

        /// Decode an unpadded base64url string. Rejects padding, characters
        /// outside the base64url alphabet, and lengths with `mod 4 == 1`.
        public static func decode(_ text: String) throws -> Data {
            if text.contains("=") {
                throw CryptoError.encoding(reason: "padded input rejected (unpadded base64url required)")
            }
            for scalar in text.unicodeScalars where !Self.isAllowed(scalar) {
                throw CryptoError.encoding(reason: "character outside base64url alphabet")
            }
            let remainder = text.count % 4
            if remainder == 1 {
                throw CryptoError.encoding(reason: "invalid base64url length: \(text.count) (mod 4 == 1)")
            }
            var standard = text
            standard = standard.replacingOccurrences(of: "-", with: "+")
            standard = standard.replacingOccurrences(of: "_", with: "/")
            if remainder == 2 {
                standard.append("==")
            } else if remainder == 3 {
                standard.append("=")
            }
            guard let data = Data(base64Encoded: standard) else {
                throw CryptoError.encoding(reason: "base64url decode failure")
            }
            return data
        }

        private static func isAllowed(_ scalar: Unicode.Scalar) -> Bool {
            switch scalar {
            case "A"..."Z", "a"..."z", "0"..."9", "-", "_":
                return true
            default:
                return false
            }
        }
    }
}
