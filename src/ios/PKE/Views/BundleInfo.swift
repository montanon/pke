// Read-only view-data for the Settings screen.
//
// The convenience initializer reads from `Bundle.main` and `UserDefaults.standard`
// so the iOS app shell can construct it with no arguments. Tests pass in
// fixture instances of both to assert fallback behavior without touching
// process-wide state.
//
// `UserDefaults` is checked first for `PKEBackendURL` so a launch flag like
// `-PKEBackendURL https://staging.example` overrides the Info.plist default
// per the story's edge case "Backend URL changes between launches via launch
// flag → Settings reflects the active URL on next render".

import Foundation

public struct BundleInfo: Equatable {

    public let appVersion: String
    public let buildNumber: String
    public let backendURL: String

    public init(appVersion: String, buildNumber: String, backendURL: String) {
        self.appVersion = appVersion
        self.buildNumber = buildNumber
        self.backendURL = backendURL
    }

    public init(bundle: Bundle = .main, defaults: UserDefaults = .standard) {
        self.init(infoDictionary: bundle.infoDictionary, defaults: defaults)
    }

    public init(infoDictionary: [String: Any]?, defaults: UserDefaults = .standard) {
        let version = infoDictionary?["CFBundleShortVersionString"] as? String
        let build = infoDictionary?["CFBundleVersion"] as? String
        let bundleBackend = infoDictionary?["PKEBackendURL"] as? String
        let defaultsBackend = defaults.string(forKey: "PKEBackendURL")

        self.appVersion = version ?? "—"
        self.buildNumber = build ?? "—"
        self.backendURL = defaultsBackend ?? bundleBackend ?? "—"
    }
}
