// Typed navigation destinations for the PKE iOS app.
//
// Used as the element type of `NavigationStack(path:)` in `PKEApp` and
// referenced by every Feature that pushes a screen. Adding a case here is a
// breaking change for every `navigationDestination(for: AppRoute.self)`
// switch; removing one is too.

import Foundation

public enum AppRoute: Hashable, CaseIterable, Sendable {
    case roleSelection
    case ownerHome
    case witnessAvailable
    case recipientGrants
    case settings
    case limitations

    public static func home(for role: Role) -> Self {
        switch role {
        case .owner: return .ownerHome
        case .witness: return .witnessAvailable
        case .recipient: return .recipientGrants
        }
    }
}
