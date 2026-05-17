// PKE iOS app entry.
//
// Wires `AppNavigationState` into the SwiftUI environment and observes
// `ScenePhase` so that returning to the foreground always re-mounts at the
// role's home, never mid-flow. Hosts the single `NavigationStack(path:)`
// driven by the typed `AppRoute` cases.
//
// UIKit-only: the `@main App` type compiles on iOS where `UIKit` is
// available. On macOS / Linux CI the type is omitted so `swift build`
// produces an otherwise-empty translation unit and the rest of the module
// (the navigation state machine, the enums, the views under
// `#if canImport(SwiftUI)`) still builds for testing.

#if canImport(UIKit) && canImport(SwiftUI)
import SwiftUI

@main
public struct PKEApp: App {
    @StateObject private var navigationState = AppNavigationState()

    public init() {}

    public var body: some Scene {
        WindowGroup {
            PKERootView()
                .environmentObject(navigationState)
        }
    }
}

struct PKERootView: View {
    @EnvironmentObject private var state: AppNavigationState
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack(path: $state.path) {
            RoleSelectionView()
                .navigationDestination(for: AppRoute.self) { route in
                    destination(for: route)
                }
        }
        .onChange(of: scenePhase) { oldPhase, newPhase in
            // Only reset on a true background→foreground return so the
            // first activation on cold launch (or transient `.inactive`
            // transitions like Control Center) does not clobber the path
            // hydrated from `UserDefaults`.
            if oldPhase == .background && newPhase == .active {
                state.resetNavigationStack()
            }
        }
    }

    @ViewBuilder
    private func destination(for route: AppRoute) -> some View {
        switch route {
        case .roleSelection:
            RoleSelectionView()
        case .ownerHome:
            OwnerHomeView()
        case .witnessAvailable:
            WitnessAvailableView()
        case .recipientGrants:
            RecipientGrantsView()
        case .settings:
            PlaceholderRouteView(title: "Settings", subtitle: "Owned by HLAM-43 Story 5.")
        case .limitations:
            PlaceholderRouteView(title: "Limitations", subtitle: "Owned by HLAM-43 Story 5.")
        }
    }
}

private struct PlaceholderRouteView: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(spacing: 16) {
            Text(title)
                .font(.largeTitle)
            Text(subtitle)
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .navigationTitle(title)
    }
}
#endif
