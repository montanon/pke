// Codable property wrapper that materialises base64url-encoded JSON strings as
// `Data` via the `PKECrypto.Base64URL` codec (HLAM-7). Decode rejects padded,
// non-ASCII, or wrong-alphabet input by surfacing the upstream
// `CryptoError.encoding(reason:)` as a `DecodingError.dataCorrupted`; encode
// emits the canonical unpadded base64url form.
//
// The wrapper conforms to `Codable`, so on a `Codable` host struct the Swift
// auto-synthesiser invokes its `init(from:)` / `encode(to:)` against a
// single-value container that holds a string — host structs see a `Data`
// field and never deal with the encoding.

import Foundation
import PKECrypto

@propertyWrapper
public struct Base64UrlData: Codable, Equatable, Hashable, Sendable {

    public var wrappedValue: Data

    public init(wrappedValue: Data) {
        self.wrappedValue = wrappedValue
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let encoded = try container.decode(String.self)
        do {
            self.wrappedValue = try PKECrypto.Base64URL.decode(encoded)
        } catch let error as CryptoError {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: error.description
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(PKECrypto.Base64URL.encode(wrappedValue))
    }
}
