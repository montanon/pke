import Foundation
import XCTest
@testable import PKEApp

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
        let info = BundleInfo(infoDictionary: nil, defaults: IsolatedDefaults.make())

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
            defaults: IsolatedDefaults.make()
        )

        XCTAssertEqual(info.appVersion, "2.0.1")
        XCTAssertEqual(info.buildNumber, "99")
        XCTAssertEqual(info.backendURL, "https://from.bundle")
    }

    func test_infoDictionaryInit_userDefaultsOverridesBundleForBackendURL() {
        let defaults = IsolatedDefaults.make()
        defaults.set("https://from.defaults", forKey: "PKEBackendURL")

        let info = BundleInfo(
            infoDictionary: ["PKEBackendURL": "https://from.bundle"],
            defaults: defaults
        )

        XCTAssertEqual(info.backendURL, "https://from.defaults")
    }
}
