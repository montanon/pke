// Boundary around the system pasteboard so `SettingsView` can be exercised
// from `swift test` on macOS-14, where `UIPasteboard` is unavailable.
//
// The iOS app shell injects `UIKitPasteboardWriter`; tests inject a
// recording fake; the macOS preview target injects `NoopPasteboardWriter`.

import Foundation

public protocol PasteboardWriting {
    func copy(_ string: String)
}

public struct NoopPasteboardWriter: PasteboardWriting {
    public init() {}
    public func copy(_ string: String) {}
}

#if canImport(UIKit)
import UIKit

public struct UIKitPasteboardWriter: PasteboardWriting {
    public init() {}

    public func copy(_ string: String) {
        UIPasteboard.general.string = string
    }
}
#endif
