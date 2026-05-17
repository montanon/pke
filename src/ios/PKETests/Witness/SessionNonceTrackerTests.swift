// Tests for `SessionNonceTracker` (HLAM-130). Covers the seven ACs plus
// the documented edge cases (idempotency, concurrency, byte-wise key
// equality).

import Foundation
import XCTest
@testable import PKEWitness

private func nonce(_ byte: UInt8) -> SessionNonce {
    SessionNonce(rawValue: Data([byte]))
}

private func witnessKey(_ byte: UInt8) -> WitnessSigningKey {
    WitnessSigningKey(rawValue: Data([byte]))
}

final class SessionNonceTrackerTests: XCTestCase {

    // MARK: AC #1 — a fresh tracker has nothing signed

    func test_freshTracker_hasSigned_returnsFalse() async {
        let tracker = SessionNonceTracker()
        let result = await tracker.hasSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        XCTAssertFalse(result)
    }

    // MARK: AC #2 — recordSigned then hasSigned returns true

    func test_recordSigned_makesPairVisible() async {
        let tracker = SessionNonceTracker()
        await tracker.recordSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        let result = await tracker.hasSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        XCTAssertTrue(result)
    }

    // MARK: AC #3 — different witness key for same nonce is independent

    func test_differentWitnessKey_sameNonce_isIndependent() async {
        let tracker = SessionNonceTracker()
        await tracker.recordSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        let result = await tracker.hasSigned(nonce: nonce(1), witnessKey: witnessKey(0xA1))
        XCTAssertFalse(result)
    }

    // MARK: AC #4 — different nonce for same witness key is independent

    func test_differentNonce_sameWitnessKey_isIndependent() async {
        let tracker = SessionNonceTracker()
        await tracker.recordSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        let result = await tracker.hasSigned(nonce: nonce(2), witnessKey: witnessKey(0xA0))
        XCTAssertFalse(result)
    }

    // MARK: AC #5 — concurrent recordSigned for the same pair is safe

    func test_concurrentRecordSigned_samePair_isSafe() async {
        let tracker = SessionNonceTracker()
        let targetNonce = nonce(0x55)
        let targetKey = witnessKey(0xBB)

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<100 {
                group.addTask {
                    await tracker.recordSigned(nonce: targetNonce, witnessKey: targetKey)
                }
            }
        }

        let result = await tracker.hasSigned(nonce: targetNonce, witnessKey: targetKey)
        XCTAssertTrue(result)
    }

    // MARK: AC #6 — a new instance does not share state with a prior one

    func test_newInstance_doesNotShareStateWithPrior() async {
        let firstTracker = SessionNonceTracker()
        await firstTracker.recordSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))

        let secondTracker = SessionNonceTracker()
        let result = await secondTracker.hasSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        XCTAssertFalse(result)
    }

    // MARK: AC #7 — declared `actor`; mutable state lives behind isolation
    // Enforced by the `actor` keyword in the source — every public method
    // is required to be awaited from outside the actor.

    // MARK: Edge case — recordSigned is idempotent

    func test_recordSigned_isIdempotent() async {
        let tracker = SessionNonceTracker()
        await tracker.recordSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        await tracker.recordSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        await tracker.recordSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        let result = await tracker.hasSigned(nonce: nonce(1), witnessKey: witnessKey(0xA0))
        XCTAssertTrue(result)
    }

    // MARK: Edge case — equality is byte-wise on the rawValue

    func test_keysWithIdenticalBytes_compareEqual() async {
        let tracker = SessionNonceTracker()
        let bytes = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        await tracker.recordSigned(
            nonce: SessionNonce(rawValue: bytes),
            witnessKey: WitnessSigningKey(rawValue: bytes)
        )
        let result = await tracker.hasSigned(
            nonce: SessionNonce(rawValue: Data([0x01, 0x02, 0x03, 0x04, 0x05])),
            witnessKey: WitnessSigningKey(rawValue: Data([0x01, 0x02, 0x03, 0x04, 0x05]))
        )
        XCTAssertTrue(result)
    }

    // MARK: claim() — atomic check-and-record returns true the first time

    func test_claim_returnsTrueOnFirstCall_falseOnSubsequent() async {
        let tracker = SessionNonceTracker()
        let first = await tracker.claim(nonce: nonce(7), witnessKey: witnessKey(0xC1))
        let second = await tracker.claim(nonce: nonce(7), witnessKey: witnessKey(0xC1))
        let third = await tracker.claim(nonce: nonce(7), witnessKey: witnessKey(0xC1))
        XCTAssertTrue(first)
        XCTAssertFalse(second)
        XCTAssertFalse(third)
    }

    // MARK: claim() — concurrent races have exactly one winner

    func test_claim_concurrentRace_hasExactlyOneWinner() async {
        let tracker = SessionNonceTracker()
        let targetNonce = nonce(0x42)
        let targetKey = witnessKey(0x99)

        let winners = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
            for _ in 0..<64 {
                group.addTask {
                    await tracker.claim(nonce: targetNonce, witnessKey: targetKey)
                }
            }
            var count = 0
            for await result in group where result {
                count += 1
            }
            return count
        }

        XCTAssertEqual(winners, 1)
        let recorded = await tracker.hasSigned(nonce: targetNonce, witnessKey: targetKey)
        XCTAssertTrue(recorded)
    }
}
