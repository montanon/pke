// Parity tests for `CanonicalJSON` against the shared `canonical_json`
// fixture corpus, plus focused depth-bound and non-finite checks.

import XCTest
@testable import PKECrypto

final class CanonicalJSONTests: XCTestCase {

    // MARK: Parametric fixture runner

    func test_canonical_json_vectors_from_bundle() throws {
        let vectors = try loadCanonicalJSONVectors(subdirectory: "test_vectors/canonical_json")
        if vectors.isEmpty {
            throw XCTSkip("no canonical_json fixtures present")
        }
        for vector in vectors {
            if vector.bundle.valid {
                try runPositiveVector(vector)
            } else {
                try runNegativeVector(vector)
            }
        }
    }

    private func runPositiveVector(_ vector: CanonicalVector) throws {
        guard let rawValue = vector.bundle.inputs.value else {
            XCTFail("canonical_json vector \(vector.bundle.name) missing inputs.value")
            return
        }
        guard let expectedHex = vector.bundle.expected.canonicalBytesHex else {
            XCTFail("canonical_json vector \(vector.bundle.name) missing expected.canonical_bytes_hex")
            return
        }
        // Re-serialise the AnyCodable input as JSON bytes, then let our strict
        // decoder build a `JSONValue` so that the test exercises both the
        // parser and the encoder end-to-end.
        let inputBytes = try JSONSerialization.data(
            withJSONObject: rawValue.unwrap(),
            options: [.fragmentsAllowed]
        )
        let value = try JSONValue.decode(inputBytes)
        let canonical = try CanonicalJSON.encode(value)
        XCTAssertEqual(
            hexEncode(canonical),
            expectedHex.lowercased(),
            "canonical_json vector \(vector.bundle.name) mismatch"
        )
    }

    private func runNegativeVector(_ vector: CanonicalVector) throws {
        guard let rawHex = vector.bundle.inputs.rawUTF8Hex else {
            XCTFail("canonical_json negative vector \(vector.bundle.name) missing inputs.raw_utf8_hex")
            return
        }
        let bytes = try decodeHexString(rawHex, name: vector.bundle.name)
        XCTAssertThrowsError(try JSONValue.decode(bytes)) { error in
            guard case .canonicalEncoding(let reason) = error as? CryptoError else {
                XCTFail("expected CryptoError.canonicalEncoding for \(vector.bundle.name), got \(error)")
                return
            }
            let expectedClass = vector.bundle.expected.error ?? ""
            if expectedClass == "duplicate_key" {
                XCTAssertTrue(
                    reason.contains("duplicate"),
                    "reason '\(reason)' missing 'duplicate' for \(vector.bundle.name)"
                )
            }
        }
    }

    // MARK: Focused unit tests

    func test_empty_object_canonical_hex() throws {
        let bytes = try CanonicalJSON.encode(.object([]))
        XCTAssertEqual(hexEncode(bytes), "7b7d")
    }

    func test_depth_64_nested_object_passes() throws {
        let nested = makeNestedObject(depth: 64)
        XCTAssertNoThrow(try CanonicalJSON.encode(nested))
    }

    func test_depth_65_nested_object_throws_max_depth() {
        let nested = makeNestedObject(depth: 65)
        XCTAssertThrowsError(try CanonicalJSON.encode(nested)) { error in
            guard case .canonicalEncoding(let reason) = error as? CryptoError else {
                XCTFail("expected CryptoError.canonicalEncoding, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("MAX_DEPTH"), "reason was \(reason)")
        }
    }

    func test_nan_double_rejected_with_non_finite_reason() {
        XCTAssertThrowsError(try CanonicalJSON.encode(.double(.nan))) { error in
            guard case .canonicalEncoding(let reason) = error as? CryptoError else {
                XCTFail("expected CryptoError.canonicalEncoding, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("non-finite"), "reason was \(reason)")
        }
    }

    // MARK: Helpers

    /// Build a `{"a": {"a": ... .null }}` chain whose deepest enclosed value
    /// (the `.null` leaf) sits at `depth` levels of nesting, matching the
    /// encoder's depth counter that starts at 1. `depth == 64` therefore
    /// produces the maximum admissible structure; `depth == 65` exceeds it.
    private func makeNestedObject(depth: Int) -> JSONValue {
        var current: JSONValue = .null
        for _ in 0..<(depth - 1) {
            current = .object([("a", current)])
        }
        return current
    }
}

// MARK: - Vector bundle decoding

private struct AnyCodableValue: Decodable {
    let storage: Any

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            storage = NSNull()
        } else if let bool = try? container.decode(Bool.self) {
            storage = bool
        } else if let int = try? container.decode(Int64.self) {
            storage = int
        } else if let double = try? container.decode(Double.self) {
            storage = double
        } else if let string = try? container.decode(String.self) {
            storage = string
        } else if let array = try? container.decode([Self].self) {
            storage = array.map { $0.unwrap() }
        } else if let object = try? container.decode([String: Self].self) {
            var mapped: [String: Any] = [:]
            for (key, value) in object {
                mapped[key] = value.unwrap()
            }
            storage = mapped
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "unsupported JSON shape"
            )
        }
    }

    func unwrap() -> Any { storage }
}

private struct CanonicalInputs: Decodable {
    let value: AnyCodableValue?
    let rawUTF8Hex: String?

    enum CodingKeys: String, CodingKey {
        case value
        case rawUTF8Hex = "raw_utf8_hex"
    }
}

private struct CanonicalExpected: Decodable {
    let canonicalBytesHex: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case canonicalBytesHex = "canonical_bytes_hex"
        case error
    }
}

private struct CanonicalBundle: Decodable {
    let name: String
    let inputs: CanonicalInputs
    let expected: CanonicalExpected
    let valid: Bool
    let notes: String?
}

private struct CanonicalVector {
    let url: URL
    let bundle: CanonicalBundle
}

private func loadCanonicalJSONVectors(subdirectory: String) throws -> [CanonicalVector] {
    var urls: [URL] = []
    if let dir = Bundle.module.url(forResource: subdirectory, withExtension: nil),
       let contents = try? FileManager.default.contentsOfDirectory(
        at: dir,
        includingPropertiesForKeys: nil
       ) {
        urls.append(contentsOf: contents.filter { $0.pathExtension == "json" })
    }
    if urls.isEmpty {
        urls.append(
            contentsOf: BundleResourceURLs.jsonResources(in: .module, subdirectory: subdirectory)
        )
    }
    // SwiftPM's `.process` flattens the resource tree, so the canonical
    // subdirectory lookup can come up empty even when the JSONs are present.
    // Fall back to a flat search and let schema-decoding gate inclusion.
    if urls.isEmpty {
        urls.append(
            contentsOf: BundleResourceURLs.jsonResources(in: .module, subdirectory: nil)
        )
    }
    let decoder = JSONDecoder()
    var loaded: [CanonicalVector] = []
    for url in urls.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
        guard let data = try? Data(contentsOf: url),
              let bundle = try? decoder.decode(CanonicalBundle.self, from: data) else {
            continue
        }
        // A canonical_json fixture is identified by having either a
        // structured `inputs.value` (positives) or `inputs.raw_utf8_hex`
        // (negatives). Bundles missing both belong to other primitives.
        guard bundle.inputs.value != nil || bundle.inputs.rawUTF8Hex != nil else {
            continue
        }
        loaded.append(CanonicalVector(url: url, bundle: bundle))
    }
    return loaded
}

// MARK: - Hex helpers

private func hexEncode(_ data: Data) -> String {
    var out = String()
    out.reserveCapacity(data.count * 2)
    for byte in data {
        out.append(String(format: "%02x", byte))
    }
    return out
}

private func decodeHexString(_ string: String, name: String) throws -> Data {
    guard string.count.isMultiple(of: 2) else {
        throw XCTSkip("vector \(name) has odd-length hex input")
    }
    var bytes = Data()
    bytes.reserveCapacity(string.count / 2)
    var index = string.startIndex
    while index < string.endIndex {
        let next = string.index(index, offsetBy: 2)
        guard let byte = UInt8(string[index..<next], radix: 16) else {
            throw XCTSkip("vector \(name) has non-hex character")
        }
        bytes.append(byte)
        index = next
    }
    return bytes
}
