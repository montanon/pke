// SHA-256 and ledger hash-chain primitives for PKECrypto.
// Mirrors the Python `pke_backend.crypto.hashing` surface and pins the
// genesis-link rule from HLAM-3 / HLAM-25.

import Crypto
import Foundation

public enum Hashing {

    /// Length, in bytes, of every SHA-256 digest accepted or produced here.
    public static let digestByteCount = 32

    /// Genesis sentinel: 32 zero bytes, used as `previous_entry_hash` on the
    /// first ledger entry per HLAM-3.
    public static let genesisPreviousEntryHash = Data(repeating: 0, count: Self.digestByteCount)

    /// SHA-256 over `data`. Returns exactly 32 bytes.
    public static func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    /// Chain-extension primitive: SHA-256 over the 64-byte concatenation
    /// `previousHash || payloadHash`. Both inputs MUST be exactly 32 bytes.
    public static func extend(previousHash: Data, payloadHash: Data) throws -> Data {
        try requireDigestLength(previousHash, label: "previousHash")
        try requireDigestLength(payloadHash, label: "payloadHash")
        var buffer = Data(capacity: Self.digestByteCount * 2)
        buffer.append(previousHash)
        buffer.append(payloadHash)
        return Self.sha256(buffer)
    }

    /// A single ledger-chain link as carried on the wire. Both fields are raw
    /// 32-byte SHA-256 digests (callers decode base64url-no-pad upstream).
    public struct ChainLink: Equatable, Sendable {
        public let entryHash: Data
        public let previousEntryHash: Data

        public init(entryHash: Data, previousEntryHash: Data) {
            self.entryHash = entryHash
            self.previousEntryHash = previousEntryHash
        }
    }

    /// Verify chain linkage from genesis through the last link.
    public static func verifyHashChain(_ chain: [ChainLink]) throws {
        guard !chain.isEmpty else {
            throw CryptoError.hashChain(reason: "empty-chain")
        }
        for (index, link) in chain.enumerated() {
            try requireLinkFieldLength(link.entryHash, index: index, field: "entryHash")
            try requireLinkFieldLength(link.previousEntryHash, index: index, field: "previousEntryHash")
        }
        guard chain[0].previousEntryHash == Self.genesisPreviousEntryHash else {
            throw CryptoError.hashChain(reason: "genesis-mismatch at index 0")
        }
        for index in 1..<chain.count where chain[index].previousEntryHash != chain[index - 1].entryHash {
            throw CryptoError.hashChain(reason: "link-mismatch at index \(index)")
        }
    }

    private static func requireDigestLength(_ value: Data, label: String) throws {
        guard value.count == Self.digestByteCount else {
            throw CryptoError.hashChain(reason: "\(label) length \(value.count) != 32")
        }
    }

    private static func requireLinkFieldLength(_ value: Data, index: Int, field: String) throws {
        guard value.count == Self.digestByteCount else {
            throw CryptoError.hashChain(
                reason: "invalid \(field) length \(value.count) at index \(index)"
            )
        }
    }
}
