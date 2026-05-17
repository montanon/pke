// Placeholder for the Witness availability screen.
//
// Real implementation lands with the F10 Witness feature; this view satisfies
// the HLAM-92 acceptance criterion that selecting Witness pushes a mountable
// screen and surfaces the cancellation banner when present.

#if canImport(SwiftUI)
import SwiftUI

public struct WitnessAvailableView: View {
    @EnvironmentObject private var state: AppNavigationState

    public init() {}

    public var body: some View {
        VStack(spacing: 16) {
            Text("Witness")
                .font(.largeTitle)
            Text("Sign nearby attestations will live here.")
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
        .navigationTitle("Witness")
    }
}
#endif
