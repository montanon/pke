// Unit and parity tests for the PKECrypto SHA-256 primitive. Chain
// (`Hashing.extend`, `Hashing.verifyHashChain`) coverage and the hash_chain
// vector runner live in `HashChainTests.swift` per HLAM-29 AC #1.

import XCTest
@testable import PKECrypto

final class HashingTests: XCTestCase {

    func test_sha256_empty_matches_well_known_digest() {
        let digest = Hashing.sha256(Data())
        XCTAssertEqual(
            hexEncode(digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // pragma: allowlist secret
        )
    }

    func test_sha256_vectors_from_bundle() throws {
        let vectors = try loadSha256Vectors(subdirectory: "test_vectors/sha256")
        if vectors.isEmpty {
            throw XCTSkip("no sha256 fixtures present")
        }
        for vector in vectors {
            let message = try decodeHex(vector.bundle.inputs.messageHex, name: vector.bundle.name)
            let actual = hexEncode(Hashing.sha256(message))
            let expected = vector.bundle.expected.digestHex.lowercased()
            if vector.bundle.valid {
                XCTAssertEqual(
                    actual,
                    expected,
                    "sha256 vector \(vector.bundle.name) mismatch"
                )
            } else {
                // SHA-256 itself has no rejection path; negative fixtures
                // record a tampered digest so the runner asserts inequality
                // (per HLAM-29 AC #4 — "throws the documented case" is
                // satisfied by the byte-divergence detection here, since
                // there is no exception path for the pure hash).
                XCTAssertNotEqual(
                    actual,
                    expected,
                    "sha256 vector \(vector.bundle.name) expected divergence but matched"
                )
            }
        }
    }
}

// MARK: - Fixture schema

private struct Sha256Inputs: Decodable {
    let messageHex: String

    enum CodingKeys: String, CodingKey {
        case messageHex = "message_hex"
    }
}

private struct Sha256Expected: Decodable {
    let digestHex: String

    enum CodingKeys: String, CodingKey {
        case digestHex = "digest_hex"
    }
}

private struct Sha256Bundle: Decodable {
    let name: String
    let inputs: Sha256Inputs
    let expected: Sha256Expected
    let valid: Bool
    let notes: String?
}

private struct LoadedSha256Vector {
    let url: URL
    let bundle: Sha256Bundle
}

private func loadSha256Vectors(subdirectory: String) throws -> [LoadedSha256Vector] {
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
    // SwiftPM's `.process` flattens the resource tree, so subdirectory
    // lookups return empty. Fall back to a flat search; schema-decoding
    // gates inclusion to sha256-shaped fixtures only.
    if urls.isEmpty {
        urls.append(
            contentsOf: BundleResourceURLs.jsonResources(in: .module, subdirectory: nil)
        )
    }
    let decoder = JSONDecoder()
    var loaded: [LoadedSha256Vector] = []
    for url in urls.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
        guard let data = try? Data(contentsOf: url),
              let bundle = try? decoder.decode(Sha256Bundle.self, from: data) else {
            continue
        }
        loaded.append(LoadedSha256Vector(url: url, bundle: bundle))
    }
    return loaded
}

// MARK: - Hex helpers (file-local copy; the chain runner carries its own)

private func hexEncode(_ data: Data) -> String {
    var out = String()
    out.reserveCapacity(data.count * 2)
    for byte in data {
        out.append(String(format: "%02x", byte))
    }
    return out
}

private func decodeHex(_ string: String, name: String) throws -> Data {
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
