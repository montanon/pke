import Foundation
import XCTest
@testable import PKEApp

final class PasteboardWritingTests: XCTestCase {

    func test_recordingWriter_capturesCopies() {
        let writer = RecordingPasteboardWriter()
        writer.copy("first")
        writer.copy("second")

        XCTAssertEqual(writer.copiedStrings, ["first", "second"])
    }

    func test_noopWriter_doesNotCrash() {
        NoopPasteboardWriter().copy("any value")
    }

    func test_protocolPolymorphismHoldsAcrossExistentials() {
        let recording = RecordingPasteboardWriter()
        let writer: any PasteboardWriting = recording
        writer.copy("via existential")

        XCTAssertEqual(recording.copiedStrings, ["via existential"])
    }
}
