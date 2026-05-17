// Unit and parity tests for the PKECrypto hash-chain primitive.
// Covers HLAM-29 AC #1-#4 for the `hash_chain` test_vector directory:
//   - one test file per primitive directory
//   - parametric runner consumes every JSON under
//     `src/shared/test_vectors/hash_chain/`
//   - positive fixtures pass byte-equality (computed entry_hash and the
//     verifier round-trip)
//   - negative fixtures throw `CryptoError.hashChain` from
//     `Hashing.verifyHashChain`

import XCTest
@testable import PKECrypto

final class HashChainTests: XCTestCase {

    // MARK: - Hashing.extend unit tests

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

    // MARK: - Hashing.verifyHashChain unit tests

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

    // MARK: - Parametric hash_chain vector runner

    func test_hash_chain_vectors_from_bundle() throws {
        let vectors = try loadHashChainVectors(subdirectory: "test_vectors/hash_chain")
        if vectors.isEmpty {
            throw XCTSkip("no hash_chain fixtures present")
        }
        for vector in vectors {
            try runChainVector(vector.bundle)
        }
    }

    // MARK: - Helpers

    private func runChainVector(_ bundle: HashChainBundle) throws {
        let computedHashes = try bundle.inputs.chain.map { try recomputeEntryHash(of: $0) }
        let links = try zip(bundle.inputs.chain, computedHashes).map { entry, computed -> Hashing.ChainLink in
            let prev = try decodeHex(entry.previousEntryHashHex, name: bundle.name)
            return Hashing.ChainLink(entryHash: computed, previousEntryHash: prev)
        }
        if bundle.valid {
            try assertPositiveChain(bundle: bundle, computedHashes: computedHashes, links: links)
        } else {
            assertNegativeChain(bundle: bundle, links: links)
        }
    }

    private func assertPositiveChain(
        bundle: HashChainBundle,
        computedHashes: [Data],
        links: [Hashing.ChainLink]
    ) throws {
        XCTAssertEqual(
            computedHashes.count,
            bundle.expected.entryHashesHex.count,
            "vector \(bundle.name): chain length mismatch"
        )
        for (index, computed) in computedHashes.enumerated() {
            let expected = try decodeHex(bundle.expected.entryHashesHex[index], name: bundle.name)
            XCTAssertEqual(
                computed,
                expected,
                "vector \(bundle.name): entry_hash mismatch at index \(index)"
            )
        }
        XCTAssertNoThrow(
            try Hashing.verifyHashChain(links),
            "vector \(bundle.name): valid chain failed verification"
        )
    }

    private func assertNegativeChain(bundle: HashChainBundle, links: [Hashing.ChainLink]) {
        XCTAssertThrowsError(
            try Hashing.verifyHashChain(links),
            "vector \(bundle.name): tampered chain expected to throw .hashChain"
        ) { error in
            guard case .hashChain = error as? CryptoError else {
                XCTFail("expected CryptoError.hashChain for \(bundle.name), got \(error)")
                return
            }
        }
    }

    private func recomputeEntryHash(of entry: HashChainEntry) throws -> Data {
        let canonical = try CanonicalJSON.encode(.object([
            ("payload_hash_hex", .string(entry.payloadHashHex)),
            ("previous_entry_hash_hex", .string(entry.previousEntryHashHex)),
            ("seq", .int(Int64(entry.seq)))
        ]))
        return Hashing.sha256(canonical)
    }

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

// MARK: - Fixture schema

private struct HashChainEntry: Decodable {
    let seq: Int
    let payloadHashHex: String
    let previousEntryHashHex: String

    enum CodingKeys: String, CodingKey {
        case seq
        case payloadHashHex = "payload_hash_hex"
        case previousEntryHashHex = "previous_entry_hash_hex"
    }
}

private struct HashChainInputs: Decodable {
    let chain: [HashChainEntry]
}

private struct HashChainExpected: Decodable {
    let entryHashesHex: [String]
    let brokenAtIndex: Int?

    enum CodingKeys: String, CodingKey {
        case entryHashesHex = "entry_hashes_hex"
        case brokenAtIndex = "broken_at_index"
    }
}

private struct HashChainBundle: Decodable {
    let name: String
    let inputs: HashChainInputs
    let expected: HashChainExpected
    let valid: Bool
    let notes: String?
}

private struct LoadedHashChainVector {
    let url: URL
    let bundle: HashChainBundle
}

private func loadHashChainVectors(subdirectory: String) throws -> [LoadedHashChainVector] {
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
    // gates inclusion to hash_chain-shaped fixtures only.
    if urls.isEmpty {
        urls.append(
            contentsOf: BundleResourceURLs.jsonResources(in: .module, subdirectory: nil)
        )
    }
    let decoder = JSONDecoder()
    var loaded: [LoadedHashChainVector] = []
    for url in urls.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
        guard let data = try? Data(contentsOf: url),
              let bundle = try? decoder.decode(HashChainBundle.self, from: data) else {
            continue
        }
        loaded.append(LoadedHashChainVector(url: url, bundle: bundle))
    }
    return loaded
}

// MARK: - Hex helpers (file-local copy; the other primitive tests carry their own)

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
