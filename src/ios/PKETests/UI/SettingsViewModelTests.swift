import Foundation
import XCTest
@testable import PKEUI

final class SettingsViewModelTests: XCTestCase {

    func test_convenienceInit_composesFingerprintFromKeyBytes() {
        let raw = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let bundleInfo = BundleInfo(
            appVersion: "1.0",
            buildNumber: "1",
            backendURL: "https://x"
        )
        let model = SettingsViewModel(
            rawSigningPublicKey: raw,
            bundleInfo: bundleInfo,
            pasteboard: NoopPasteboardWriter()
        )

        XCTAssertEqual(model.fingerprintDisplay, Fingerprint.display(rawPublicKey: raw))
        XCTAssertEqual(model.fingerprintFullHex, Fingerprint.fullHex(rawPublicKey: raw))
    }

    func test_convenienceInit_copiesBundleInfoFields() {
        let bundleInfo = BundleInfo(
            appVersion: "2.5",
            buildNumber: "42",
            backendURL: "https://staging.example"
        )
        let model = SettingsViewModel(
            rawSigningPublicKey: Data([0x00]),
            bundleInfo: bundleInfo,
            pasteboard: NoopPasteboardWriter()
        )

        XCTAssertEqual(model.appVersion, "2.5")
        XCTAssertEqual(model.buildNumber, "42")
        XCTAssertEqual(model.backendURL, "https://staging.example")
    }

    func test_copyActionWritesFullHexToPasteboard() {
        let raw = Data([0xCA, 0xFE, 0xBA, 0xBE])
        let writer = RecordingPasteboardWriter()
        let model = SettingsViewModel(
            rawSigningPublicKey: raw,
            bundleInfo: BundleInfo(appVersion: "x", buildNumber: "x", backendURL: "x"),
            pasteboard: writer
        )

        model.pasteboard.copy(model.fingerprintFullHex)

        XCTAssertEqual(writer.copiedStrings, ["cafebabe"])
    }
}
