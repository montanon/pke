// Per-test `UserDefaults` suite so persistence assertions never leak into
// the host's `.standard` defaults. Mirrors the in-memory-fake pattern from
// `PKETests/Identity/InMemoryKeychainFake.swift`.

import Foundation

enum IsolatedDefaults {
    static func make() -> UserDefaults {
        let suiteName = "pke.tests.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            preconditionFailure("UserDefaults(suiteName:) returned nil for \(suiteName)")
        }
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }
}
