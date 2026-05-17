// Tests for the `AttestationStrength` bucket mapper (HLAM-131).
// Covers the six ACs plus the explicit threshold-boundary and large-value
// edges.

import Foundation
import XCTest
@testable import PKEWitness

final class AttestationStrengthTests: XCTestCase {

    // MARK: AC #1 — zero witnesses → AttestationStrength.none

    func test_bucket_forZero_isNone() {
        XCTAssertEqual(AttestationStrength.bucket(for: 0), AttestationStrength.none)
    }

    // MARK: AC #2 — 1 and 2 → .low

    func test_bucket_forOneAndTwo_isLow() {
        XCTAssertEqual(AttestationStrength.bucket(for: 1), .low)
        XCTAssertEqual(AttestationStrength.bucket(for: 2), .low)
    }

    // MARK: AC #3 — 3 and 9 → .medium

    func test_bucket_forThreeAndNine_isMedium() {
        XCTAssertEqual(AttestationStrength.bucket(for: 3), .medium)
        XCTAssertEqual(AttestationStrength.bucket(for: 9), .medium)
    }

    // MARK: AC #4 — 10 and large counts → .high

    func test_bucket_forTenAndHundred_isHigh() {
        XCTAssertEqual(AttestationStrength.bucket(for: 10), .high)
        XCTAssertEqual(AttestationStrength.bucket(for: 100), .high)
    }

    // MARK: AC #5 — negative input → AttestationStrength.none (defensive)

    func test_bucket_forNegativeInput_isNoneDefensively() {
        XCTAssertEqual(AttestationStrength.bucket(for: -1), AttestationStrength.none)
        XCTAssertEqual(AttestationStrength.bucket(for: Int.min), AttestationStrength.none)
    }

    // MARK: AC #6 — exactly the four documented cases

    func test_cases_areExactlyFourDocumentedValues() {
        XCTAssertEqual(
            Set(AttestationStrength.allCases),
            Set([AttestationStrength.none, .low, .medium, .high])
        )
        XCTAssertEqual(AttestationStrength.allCases.count, 4)
    }

    // MARK: Edge — explicit threshold boundaries (2 → 3 and 9 → 10)

    func test_bucket_boundariesAreExactlyAtThresholds() {
        XCTAssertEqual(AttestationStrength.bucket(for: 2), .low)
        XCTAssertEqual(AttestationStrength.bucket(for: 3), .medium)
        XCTAssertEqual(AttestationStrength.bucket(for: 9), .medium)
        XCTAssertEqual(AttestationStrength.bucket(for: 10), .high)
    }

    // MARK: Edge — Int.max → .high

    func test_bucket_forIntMax_isHigh() {
        XCTAssertEqual(AttestationStrength.bucket(for: Int.max), .high)
    }
}
