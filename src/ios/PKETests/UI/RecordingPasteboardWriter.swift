// In-memory `PasteboardWriting` fake. Captures every `copy(_:)` call so
// tests can assert the copy-button behavior without UIKit.

import Foundation
@testable import PKEUI

final class RecordingPasteboardWriter: PasteboardWriting {
    private(set) var copiedStrings: [String] = []

    func copy(_ string: String) {
        copiedStrings.append(string)
    }
}
