// MVP caveat screen. Renders `Limitations.notMVP` (mirroring the
// `## Explicitly not MVP` section of `context/09_mvp_scope.md`) and
// `Limitations.trustBoundaries` (the four trust-boundary caveats pinned
// by HLAM-95 AC#2) as two grouped lists.

#if canImport(SwiftUI)
import SwiftUI

public struct LimitationsView: View {

    public init() {}

    public var body: some View {
        Form {
            Section("Not in MVP") {
                ForEach(Limitations.notMVP, id: \.self) { caveat in
                    Text("• \(caveat)")
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Section("Trust boundaries") {
                ForEach(Limitations.trustBoundaries, id: \.self) { caveat in
                    Text("• \(caveat)")
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .navigationTitle("Limitations")
    }
}
#endif
