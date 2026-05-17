// User-selectable role for the PKE iOS app.
//
// Roles are non-exclusive across the install lifetime — the same install can
// move between Owner, Witness, and Recipient at any time. The raw `String`
// value is what `AppNavigationState` writes to `UserDefaults` under the key
// `AppNavigationState.lastRoleKey`, so changing a case's raw value is a
// migration.

import Foundation

public enum Role: String, CaseIterable, Codable, Hashable, Sendable {
    case owner
    case witness
    case recipient

    public var displayName: String {
        switch self {
        case .owner: return "Owner"
        case .witness: return "Witness"
        case .recipient: return "Recipient"
        }
    }
}
