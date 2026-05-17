import Foundation
import XCTest
@testable import PKEUI

final class BundleInfoTests: XCTestCase {

    func test_designatedInit_storesValues() {
        let info = BundleInfo(
            appVersion: "1.2.3",
            buildNumber: "456",
            backendURL: "https://api.example"
        )

        XCTAssertEqual(info.appVersion, "1.2.3")
        XCTAssertEqual(info.buildNumber, "456")
        XCTAssertEqual(info.backendURL, "https://api.example")
    }

    func test_convenienceInit_fallsBackToEmDashForMissingKeys() {
        let info = BundleInfo(
            bundle: StubBundle(info: nil),
            defaults: emptyDefaults()
        )

        XCTAssertEqual(info.appVersion, "—")
        XCTAssertEqual(info.buildNumber, "—")
        XCTAssertEqual(info.backendURL, "—")
    }

    func test_convenienceInit_readsBundleInfoWhenPresent() {
        let info = BundleInfo(
            bundle: StubBundle(info: [
                "CFBundleShortVersionString": "2.0.1",
                "CFBundleVersion": "99",
                "PKEBackendURL": "https://from.bundle"
            ]),
            defaults: emptyDefaults()
        )

        XCTAssertEqual(info.appVersion, "2.0.1")
        XCTAssertEqual(info.buildNumber, "99")
        XCTAssertEqual(info.backendURL, "https://from.bundle")
    }

    func test_convenienceInit_userDefaultsOverridesBundleForBackendURL() {
        let defaults = emptyDefaults()
        defaults.set("https://from.defaults", forKey: "PKEBackendURL")

        let info = BundleInfo(
            bundle: StubBundle(info: ["PKEBackendURL": "https://from.bundle"]),
            defaults: defaults
        )

        XCTAssertEqual(info.backendURL, "https://from.defaults")
    }

    // MARK: - Helpers

    private func emptyDefaults() -> UserDefaults {
        // A dedicated suite avoids polluting the test runner's standard
        // defaults across cases.
        let suiteName = "BundleInfoTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)
        defaults?.removePersistentDomain(forName: suiteName)
        return defaults ?? UserDefaults()
    }
}

private final class StubBundle: Bundle, @unchecked Sendable {
    private let stubInfo: [String: Any]?

    init(info: [String: Any]?) {
        self.stubInfo = info
        super.init()
    }

    override var infoDictionary: [String: Any]? {
        stubInfo
    }
}
