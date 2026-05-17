import SwiftUI

struct ContentView: View {

    var body: some View {
        VStack(spacing: 12) {
            Text("PKE")
                .font(.largeTitle)
                .bold()
            Text("Verifiable Custody")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
