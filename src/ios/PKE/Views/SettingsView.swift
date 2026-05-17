// Read-only Settings screen — device fingerprint, version, backend URL,
// and a navigation link into `LimitationsView`. The screen has no mutation
// surface in MVP per HLAM-95; the only interaction is the copy button,
// which routes through the injected `PasteboardWriting`.

#if canImport(SwiftUI)
import SwiftUI

public struct SettingsView: View {

    private let model: SettingsViewModel

    public init(model: SettingsViewModel) {
        self.model = model
    }

    public var body: some View {
        Form {
            Section {
                fingerprintRow
                LabeledContent("App version", value: "\(model.appVersion) (\(model.buildNumber))")
                LabeledContent("Backend URL") {
                    Text(model.backendURL)
                        .textSelection(.enabled)
                        .multilineTextAlignment(.trailing)
                }
            }
            Section {
                NavigationLink("View Limitations") {
                    LimitationsView()
                }
            }
        }
        .navigationTitle("Settings")
    }

    private var fingerprintRow: some View {
        LabeledContent("Device fingerprint") {
            HStack(spacing: 8) {
                Text(model.fingerprintDisplay)
                    .monospaced()
                    .textSelection(.enabled)
                Button {
                    model.pasteboard.copy(model.fingerprintFullHex)
                } label: {
                    Image(systemName: "doc.on.clipboard")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Copy device fingerprint")
                .accessibilityHint("Copies the full hex public key to the pasteboard")
            }
        }
    }
}
#endif
