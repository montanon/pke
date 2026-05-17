import XCTest
@testable import PKECrypto

final class JSONValueTests: XCTestCase {
    func testNestedStructuresEqualWhenStructurallyEqual() {
        let left: JSONValue = .object([
            "outer": .array([
                .object(["inner": .integer(1)]),
                .null,
                .bool(true)
            ])
        ])
        let right: JSONValue = .object([
            "outer": .array([
                .object(["inner": .integer(1)]),
                .null,
                .bool(true)
            ])
        ])
        XCTAssertEqual(left, right)
    }

    func testIntegerZeroNotEqualToBoolFalse() {
        XCTAssertNotEqual(JSONValue.integer(0), JSONValue.bool(false))
    }

    func testNullEqualsNull() {
        XCTAssertEqual(JSONValue.null, JSONValue.null)
    }
}
