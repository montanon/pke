// Role-selection landing screen for the PKE iOS app.
//
// First view a fresh install sees. Tapping a role button hands off to
// `AppNavigationState.select(role:)`, which sets the role, persists it via
// `UserDefaults`, and pushes the role's home route onto the navigation
// path.

#if canImport(SwiftUI)
import SwiftUI

public struct RoleSelectionView: View {
    @EnvironmentObject private var state: AppNavigationState

    public init() {}

    public var body: some View {
        VStack(spacing: 24) {
            Text("Select your role")
                .font(.largeTitle)
                .multilineTextAlignment(.center)
            Text("You can switch roles at any time.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            VStack(spacing: 12) {
                ForEach(Role.allCases, id: \.self) { role in
                    Button {
                        state.select(role: role)
                    } label: {
                        Text(role.displayName)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityLabel("Continue as \(role.displayName)")
                }
            }
            Spacer()
        }
        .padding()
        .navigationTitle("PKE")
    }
}
#endif
