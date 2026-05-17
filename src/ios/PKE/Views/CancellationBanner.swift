// Banner surfacing a "cancelled by user" notice from
// `AppNavigationState.cancellationNotice`.
//
// Reused by every role placeholder so the consumer-facing cancellation copy
// stays consistent. Dismiss tap clears the notice via the supplied closure.

#if canImport(SwiftUI)
import SwiftUI

struct CancellationBanner: View {
    let notice: String
    let onDismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Text(notice)
                .font(.footnote)
                .multilineTextAlignment(.leading)
            Spacer(minLength: 0)
            Button(action: onDismiss) {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Dismiss cancellation notice")
        }
        .padding(12)
        .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
    }
}
#endif
