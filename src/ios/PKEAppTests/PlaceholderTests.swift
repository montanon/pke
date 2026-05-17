import PKEApp
import XCTest

final class PlaceholderTests: XCTestCase {

    func testAppModuleLoads() {
        XCTAssertTrue(String(describing: PKEApp.self).contains("PKEApp"))
    }
}
