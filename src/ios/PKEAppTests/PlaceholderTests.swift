import XCTest
@testable import PKE

final class PlaceholderTests: XCTestCase {

    func testAppModuleLoads() {
        XCTAssertTrue(String(describing: PKEApp.self).contains("PKEApp"))
    }
}
