// Placeholder for the Recipient grants screen.
//
// Real implementation lands with the F11 Recipient feature; this view
// satisfies the HLAM-92 acceptance criterion that selecting Recipient pushes
// a mountable screen and surfaces the cancellation banner when present.

#if canImport(SwiftUI)
import SwiftUI

public struct RecipientGrantsView: View {
    @EnvironmentObject private var state: AppNavigationState

    public init() {}

    public var body: some View {
        VStack(spacing: 16) {
            Text("Recipient")
                .font(.largeTitle)
            Text("Inspect grants and decrypt evidence will live here.")
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
        .navigationTitle("Recipient")
    }
}
#endif
