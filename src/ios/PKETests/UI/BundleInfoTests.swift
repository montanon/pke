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

    func test_infoDictionaryInit_fallsBackToEmDashForMissingKeys() {
        let info = BundleInfo(infoDictionary: nil, defaults: emptyDefaults())

        XCTAssertEqual(info.appVersion, "—")
        XCTAssertEqual(info.buildNumber, "—")
        XCTAssertEqual(info.backendURL, "—")
    }

    func test_infoDictionaryInit_readsValuesWhenPresent() {
        let info = BundleInfo(
            infoDictionary: [
                "CFBundleShortVersionString": "2.0.1",
                "CFBundleVersion": "99",
                "PKEBackendURL": "https://from.bundle"
            ],
            defaults: emptyDefaults()
        )

        XCTAssertEqual(info.appVersion, "2.0.1")
        XCTAssertEqual(info.buildNumber, "99")
        XCTAssertEqual(info.backendURL, "https://from.bundle")
    }

    func test_infoDictionaryInit_userDefaultsOverridesBundleForBackendURL() {
        let defaults = emptyDefaults()
        defaults.set("https://from.defaults", forKey: "PKEBackendURL")

        let info = BundleInfo(
            infoDictionary: ["PKEBackendURL": "https://from.bundle"],
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
