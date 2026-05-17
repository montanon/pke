// Unit and parity tests for the PKECrypto Hashing module.
// Covers AC #1-#4 and the parametric test-vector runner stub from HLAM-25.

import XCTest
@testable import PKECrypto

final class HashingTests: XCTestCase {

    // MARK: SHA-256

    func test_sha256_empty_matches_well_known_digest() {
        let digest = Hashing.sha256(Data())
        XCTAssertEqual(
            hexEncode(digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // pragma: allowlist secret
        )
    }

    // MARK: extend

    func test_extend_rejects_non_32_byte_inputs() {
        let short = Data(repeating: 0xAA, count: 31)
        let long = Data(repeating: 0xBB, count: 33)
        let valid = Data(repeating: 0xCC, count: 32)

        assertThrowsHashChain(try Hashing.extend(previousHash: short, payloadHash: valid))
        assertThrowsHashChain(try Hashing.extend(previousHash: valid, payloadHash: long))
    }

    func test_extend_is_deterministic_concatenation() throws {
        let prev = Data(repeating: 0xAA, count: 32)
        let payload = Data(repeating: 0xBB, count: 32)
        let extended = try Hashing.extend(previousHash: prev, payloadHash: payload)
        let expected = Hashing.sha256(prev + payload)
        XCTAssertEqual(extended, expected)
        XCTAssertEqual(extended.count, 32)
    }

    // MARK: verifyHashChain

    func test_verifyHashChain_valid_genesis_chain_passes() throws {
        let chain = makeValidThreeLinkChain()
        XCTAssertNoThrow(try Hashing.verifyHashChain(chain))
    }

    func test_verifyHashChain_single_link_with_genesis_passes() {
        let only = Hashing.ChainLink(
            entryHash: Hashing.sha256(Data("solo".utf8)),
            previousEntryHash: Hashing.genesisPreviousEntryHash
        )
        XCTAssertNoThrow(try Hashing.verifyHashChain([only]))
    }

    func test_verifyHashChain_mutated_link_throws_hashChain() {
        var chain = makeValidThreeLinkChain()
        let mutated = Hashing.ChainLink(
            entryHash: chain[1].entryHash,
            previousEntryHash: Data(repeating: 0x42, count: 32)
        )
        chain[1] = mutated
        XCTAssertThrowsError(try Hashing.verifyHashChain(chain)) { error in
            guard case .hashChain(let reason) = error as? CryptoError else {
                XCTFail("expected CryptoError.hashChain, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("link-mismatch"), "reason was \(reason)")
        }
    }

    func test_verifyHashChain_non_zero_genesis_throws_hashChain() {
        let bad = Hashing.ChainLink(
            entryHash: Hashing.sha256(Data("x".utf8)),
            previousEntryHash: Data(repeating: 0x01, count: 32)
        )
        XCTAssertThrowsError(try Hashing.verifyHashChain([bad])) { error in
            guard case .hashChain(let reason) = error as? CryptoError else {
                XCTFail("expected CryptoError.hashChain, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("genesis-mismatch"), "reason was \(reason)")
        }
    }

    func test_verifyHashChain_empty_chain_throws_hashChain() {
        XCTAssertThrowsError(try Hashing.verifyHashChain([])) { error in
            guard case .hashChain(let reason) = error as? CryptoError else {
                XCTFail("expected CryptoError.hashChain, got \(error)")
                return
            }
            XCTAssertEqual(reason, "empty-chain")
        }
    }

    func test_verifyHashChain_wrong_length_field_throws_hashChain() {
        let bad = Hashing.ChainLink(
            entryHash: Data(repeating: 0xAB, count: 31),
            previousEntryHash: Hashing.genesisPreviousEntryHash
        )
        XCTAssertThrowsError(try Hashing.verifyHashChain([bad])) { error in
            guard case .hashChain(let reason) = error as? CryptoError else {
                XCTFail("expected CryptoError.hashChain, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("31"), "reason was \(reason)")
            XCTAssertTrue(reason.contains("entryHash"), "reason was \(reason)")
        }
    }

    // MARK: Parametric test-vector runners

    func test_sha256_vectors_from_bundle() throws {
        let vectors = try loadVectors(subdirectory: "test_vectors/sha256")
        if vectors.isEmpty {
            throw XCTSkip("no sha256 fixtures present")
        }
        for vector in vectors {
            guard let messageHex = vector.bundle.inputs.message else {
                XCTFail("sha256 vector \(vector.bundle.name) missing inputs.message")
                continue
            }
            guard let digestHex = vector.bundle.expected.digest else {
                XCTFail("sha256 vector \(vector.bundle.name) missing expected.digest")
                continue
            }
            let message = try decodeHex(messageHex, name: vector.bundle.name)
            let actual = Hashing.sha256(message)
            XCTAssertEqual(
                hexEncode(actual),
                digestHex.lowercased(),
                "sha256 vector \(vector.bundle.name) mismatch"
            )
        }
    }

    func test_hash_chain_vectors_from_bundle() throws {
        let vectors = try loadVectors(subdirectory: "test_vectors/hash_chain")
        if vectors.isEmpty {
            throw XCTSkip("no hash_chain fixtures present")
        }
        for vector in vectors {
            guard let prevHex = vector.bundle.inputs.previousHash,
                  let payloadHex = vector.bundle.inputs.payloadHash else {
                XCTFail("hash_chain vector \(vector.bundle.name) missing inputs")
                continue
            }
            let prev = try decodeHex(prevHex, name: vector.bundle.name)
            let payload = try decodeHex(payloadHex, name: vector.bundle.name)
            if vector.bundle.valid {
                guard let expectedHex = vector.bundle.expected.nextHash else {
                    XCTFail("hash_chain vector \(vector.bundle.name) missing expected.next_hash")
                    continue
                }
                let actual = try Hashing.extend(previousHash: prev, payloadHash: payload)
                XCTAssertEqual(
                    hexEncode(actual),
                    expectedHex.lowercased(),
                    "hash_chain vector \(vector.bundle.name) mismatch"
                )
            } else {
                XCTAssertThrowsError(try Hashing.extend(previousHash: prev, payloadHash: payload)) { error in
                    guard case .hashChain = error as? CryptoError else {
                        XCTFail("expected CryptoError.hashChain for \(vector.bundle.name), got \(error)")
                        return
                    }
                }
            }
        }
    }

    // MARK: Helpers

    private func makeValidThreeLinkChain() -> [Hashing.ChainLink] {
        let entry0 = Hashing.sha256(Data("a".utf8))
        let entry1 = Hashing.sha256(Data("b".utf8))
        let entry2 = Hashing.sha256(Data("c".utf8))
        return [
            Hashing.ChainLink(entryHash: entry0, previousEntryHash: Hashing.genesisPreviousEntryHash),
            Hashing.ChainLink(entryHash: entry1, previousEntryHash: entry0),
            Hashing.ChainLink(entryHash: entry2, previousEntryHash: entry1)
        ]
    }

    private func assertThrowsHashChain(
        _ expression: @autoclosure () throws -> Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            guard case .hashChain = error as? CryptoError else {
                XCTFail("expected CryptoError.hashChain, got \(error)", file: file, line: line)
                return
            }
        }
    }
}

// MARK: - Vector bundle decoding

private struct VectorInputs: Decodable {
    let message: String?
    let previousHash: String?
    let payloadHash: String?

    enum CodingKeys: String, CodingKey {
        case message
        case previousHash = "previous_hash"
        case payloadHash = "payload_hash"
    }
}

private struct VectorExpected: Decodable {
    let digest: String?
    let nextHash: String?

    enum CodingKeys: String, CodingKey {
        case digest
        case nextHash = "next_hash"
    }
}

private struct VectorBundle: Decodable {
    let name: String
    let inputs: VectorInputs
    let expected: VectorExpected
    let valid: Bool
    let notes: String?
}

private struct LoadedVector {
    let url: URL
    let bundle: VectorBundle
}

private func loadVectors(subdirectory: String) throws -> [LoadedVector] {
    var urls: [URL] = []
    if let dir = Bundle.module.url(forResource: subdirectory, withExtension: nil),
       let contents = try? FileManager.default.contentsOfDirectory(
        at: dir,
        includingPropertiesForKeys: nil
       ) {
        urls.append(contentsOf: contents.filter { $0.pathExtension == "json" })
    }
    if urls.isEmpty,
       let flattened = Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: subdirectory) {
        urls.append(contentsOf: flattened)
    }
    let decoder = JSONDecoder()
    var loaded: [LoadedVector] = []
    for url in urls.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
        let data = try Data(contentsOf: url)
        let bundle = try decoder.decode(VectorBundle.self, from: data)
        loaded.append(LoadedVector(url: url, bundle: bundle))
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
