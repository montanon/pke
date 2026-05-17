// Coverage for `AppRoute` — exhaustive case set (AC#6) and role-home
// mapping consumed by `AppNavigationState.select(role:)`.

import XCTest
@testable import PKEApp

final class AppRouteTests: XCTestCase {

    func testHasExactlySixCases() {
        XCTAssertEqual(AppRoute.allCases.count, 6)
    }

    func testContainsAllSpecifiedCases() {
        let actual = Set(AppRoute.allCases)
        let expected: Set<AppRoute> = [
            .roleSelection,
            .ownerHome,
            .witnessAvailable,
            .recipientGrants,
            .settings,
            .limitations
        ]
        XCTAssertEqual(actual, expected)
    }

    func testHomeForOwnerIsOwnerHome() {
        XCTAssertEqual(AppRoute.home(for: .owner), .ownerHome)
    }

    func testHomeForWitnessIsWitnessAvailable() {
        XCTAssertEqual(AppRoute.home(for: .witness), .witnessAvailable)
    }

    func testHomeForRecipientIsRecipientGrants() {
        XCTAssertEqual(AppRoute.home(for: .recipient), .recipientGrants)
    }
}
