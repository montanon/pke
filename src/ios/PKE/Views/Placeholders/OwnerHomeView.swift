// Placeholder for the Owner home screen.
//
// Real implementation lands with the F9 Owner feature; this view satisfies
// the HLAM-92 acceptance criterion that selecting Owner pushes a mountable
// screen and renders the cancellation banner when present.

#if canImport(SwiftUI)
import SwiftUI

public struct OwnerHomeView: View {
    @EnvironmentObject private var state: AppNavigationState

    public init() {}

    public var body: some View {
        VStack(spacing: 16) {
            Text("Owner")
                .font(.largeTitle)
            Text("Capture and seal evidence will live here.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if let notice = state.cancellationNotice {
                CancellationBanner(notice: notice) {
                    state.dismissCancellationNotice()
                }
            }
        }
        .padding()
        .navigationTitle("Owner")
    }
}
#endif
