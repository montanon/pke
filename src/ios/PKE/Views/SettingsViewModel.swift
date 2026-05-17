// Composition of every value `SettingsView` needs to render.
//
// The host (eventual `PKEApp` shell in HLAM-92) builds this from a freshly
// loaded `DeviceIdentity` and the process bundle. The view itself stays a
// pure renderer with no I/O — every transformation has already happened by
// the time the view sees the model.

import Foundation

public struct SettingsViewModel {

    public let fingerprintDisplay: String
    public let fingerprintFullHex: String
    public let appVersion: String
    public let buildNumber: String
    public let backendURL: String
    public let pasteboard: any PasteboardWriting

    public init(
        fingerprintDisplay: String,
        fingerprintFullHex: String,
        appVersion: String,
        buildNumber: String,
        backendURL: String,
        pasteboard: any PasteboardWriting
    ) {
        self.fingerprintDisplay = fingerprintDisplay
        self.fingerprintFullHex = fingerprintFullHex
        self.appVersion = appVersion
        self.buildNumber = buildNumber
        self.backendURL = backendURL
        self.pasteboard = pasteboard
    }

    public init(
        rawSigningPublicKey: Data,
        bundleInfo: BundleInfo = BundleInfo(),
        pasteboard: any PasteboardWriting
    ) {
        self.init(
            fingerprintDisplay: Fingerprint.display(rawPublicKey: rawSigningPublicKey),
            fingerprintFullHex: Fingerprint.fullHex(rawPublicKey: rawSigningPublicKey),
            appVersion: bundleInfo.appVersion,
            buildNumber: bundleInfo.buildNumber,
            backendURL: bundleInfo.backendURL,
            pasteboard: pasteboard
        )
    }
}
