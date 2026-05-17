// Bridge from `Encodable` protocol payloads to the canonical `JSONValue`
// pipeline used by every signed surface (HLAM-7). The extension serialises a
// value through `JSONEncoder`, then re-parses the bytes with the strict
// `JSONValue` parser; any non-canonical artefacts the encoder might emit
// (escape choices, key order) are normalised by the subsequent
// `CanonicalJSON.encode` step the caller invokes.
//
// `AnyStringKey` and `requireNoUnknownKeys` are internal helpers that the
// payload models share to implement schema-`additionalProperties: false`
// strictness at decode time.

import Foundation
import PKECrypto

public extension Encodable {

    /// Encode `self` via `JSONEncoder` and re-parse with `JSONValue.decode`,
    /// producing the strongly typed value tree the canonical encoder consumes.
    func toJSONValue() throws -> JSONValue {
        let encoder = JSONEncoder()
        let data = try encoder.encode(self)
        return try JSONValue.decode(data)
    }
}

internal struct AnyStringKey: CodingKey {

    let stringValue: String
    var intValue: Int? { nil }

    init(stringValue: String) {
        self.stringValue = stringValue
    }

    // swiftlint:disable implicit_return
    init?(intValue: Int) {
        return nil
    }
    // swiftlint:enable implicit_return
}

internal func requireNoUnknownKeys<K>(
    in decoder: Decoder,
    against keyType: K.Type
) throws where K: CodingKey, K: CaseIterable {
    let container = try decoder.container(keyedBy: AnyStringKey.self)
    let known = Set(K.allCases.map { $0.stringValue })
    for key in container.allKeys where !known.contains(key.stringValue) {
        throw DecodingError.dataCorruptedError(
            forKey: key,
            in: container,
            debugDescription: "unknown key '\(key.stringValue)'"
        )
    }
}
