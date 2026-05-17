// Coverage for `Role` — exhaustive cases and raw-value round trip.
// Pins the persistence contract for `@AppStorage("pke.lastRole")`.

import XCTest
@testable import PKEApp

final class RoleTests: XCTestCase {

    func testHasExactlyThreeCases() {
        XCTAssertEqual(Role.allCases, [.owner, .witness, .recipient])
    }

    func testRawValuesArePinnedLowercase() {
        XCTAssertEqual(Role.owner.rawValue, "owner")
        XCTAssertEqual(Role.witness.rawValue, "witness")
        XCTAssertEqual(Role.recipient.rawValue, "recipient")
    }

    func testRawValueRoundTrip() {
        for role in Role.allCases {
            XCTAssertEqual(Role(rawValue: role.rawValue), role)
        }
    }

    func testUnknownRawValueReturnsNil() {
        XCTAssertNil(Role(rawValue: "garbage"))
        XCTAssertNil(Role(rawValue: ""))
        XCTAssertNil(Role(rawValue: "OWNER"))
    }

    func testCodableRoundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        for role in Role.allCases {
            let data = try encoder.encode(role)
            let decoded = try decoder.decode(Role.self, from: data)
            XCTAssertEqual(decoded, role)
        }
    }

    func testDisplayNameMatchesUserFacingCopy() {
        XCTAssertEqual(Role.owner.displayName, "Owner")
        XCTAssertEqual(Role.witness.displayName, "Witness")
        XCTAssertEqual(Role.recipient.displayName, "Recipient")
    }
}
