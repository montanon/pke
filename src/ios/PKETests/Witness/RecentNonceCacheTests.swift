// Tests for the bounded recent-nonce replay cache used by
// `WitnessSessionMachine` (HLAM-110). Covers AC #6 (replay rejection
// semantics — surfaced via `contains`) and AC #7 (64-entry bound with
// FIFO eviction).

import XCTest
@testable import PKEWitness

final class RecentNonceCacheTests: XCTestCase {

    // MARK: - AC #7 — empty cache

    func test_cache_emptyDoesNotContain() {
        let cache = RecentNonceCache(capacity: 64)
        XCTAssertFalse(cache.contains(Data([0x01])))
    }

    // MARK: - AC #6 / #7 — insertion semantics

    func test_cache_insertReturnsTrueOnFirstSight() {
        var cache = RecentNonceCache(capacity: 64)
        let nonce = Data([0x01, 0x02, 0x03])

        XCTAssertTrue(cache.insert(nonce))
        XCTAssertTrue(cache.contains(nonce))
    }

    func test_cache_insertReturnsFalseOnDuplicate() {
        var cache = RecentNonceCache(capacity: 64)
        let nonce = Data([0xAA])

        XCTAssertTrue(cache.insert(nonce))
        XCTAssertFalse(cache.insert(nonce))
        XCTAssertTrue(cache.contains(nonce))
    }

    // MARK: - AC #7 — bounded eviction

    func test_cache_evictsOldestOnOverflow() {
        var cache = RecentNonceCache(capacity: 64)

        // Fill exactly to capacity with 64 distinct nonces.
        for index in 0..<64 {
            XCTAssertTrue(cache.insert(makeNonce(index)))
        }
        XCTAssertTrue(cache.contains(makeNonce(0)))
        XCTAssertTrue(cache.contains(makeNonce(63)))

        // 65th distinct insert evicts the head.
        XCTAssertTrue(cache.insert(makeNonce(64)))
        XCTAssertFalse(cache.contains(makeNonce(0)))
        XCTAssertTrue(cache.contains(makeNonce(1)))
        XCTAssertTrue(cache.contains(makeNonce(64)))
    }

    func test_cache_duplicateInsertDoesNotEvict() {
        var cache = RecentNonceCache(capacity: 64)
        for index in 0..<64 {
            _ = cache.insert(makeNonce(index))
        }

        // Re-insert one already-present nonce. The head MUST NOT be evicted.
        XCTAssertFalse(cache.insert(makeNonce(10)))
        XCTAssertTrue(cache.contains(makeNonce(0)))
        XCTAssertTrue(cache.contains(makeNonce(63)))
    }

    func test_cache_repeatedOverflowMaintainsFifoOrder() {
        var cache = RecentNonceCache(capacity: 3)
        XCTAssertTrue(cache.insert(makeNonce(1)))
        XCTAssertTrue(cache.insert(makeNonce(2)))
        XCTAssertTrue(cache.insert(makeNonce(3)))
        // Now full; insert 4 evicts 1.
        XCTAssertTrue(cache.insert(makeNonce(4)))
        XCTAssertFalse(cache.contains(makeNonce(1)))
        XCTAssertTrue(cache.contains(makeNonce(2)))
        // Insert 5 evicts 2.
        XCTAssertTrue(cache.insert(makeNonce(5)))
        XCTAssertFalse(cache.contains(makeNonce(2)))
        XCTAssertTrue(cache.contains(makeNonce(3)))
        XCTAssertTrue(cache.contains(makeNonce(4)))
        XCTAssertTrue(cache.contains(makeNonce(5)))
    }

    // MARK: - Helpers

    private func makeNonce(_ value: Int) -> Data {
        // Encode the index as 4 little-endian bytes for fixture clarity.
        var data = Data(count: 4)
        data[0] = UInt8(value & 0xFF)
        data[1] = UInt8((value >> 8) & 0xFF)
        data[2] = UInt8((value >> 16) & 0xFF)
        data[3] = UInt8((value >> 24) & 0xFF)
        return data
    }
}
