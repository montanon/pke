import Foundation
import XCTest
@testable import PKEUI

/// Guards the contract that `Limitations.notMVP` mirrors the
/// `## Explicitly not MVP` section of `context/09_mvp_scope.md` bullet-for-
/// bullet. If a maintainer edits the doc without updating
/// `src/ios/PKE/Views/Limitations.swift`, this test fails with a precise
/// diff naming both files.
final class LimitationsDocParityTests: XCTestCase {

    func test_notMVPMatchesContextDocBulletForBullet() throws {
        let docURL = try mvpScopeDocURL()
        let contents = try String(contentsOf: docURL, encoding: .utf8)
        let extracted = extractExplicitlyNotMVPBullets(from: contents)

        XCTAssertFalse(
            extracted.isEmpty,
            """
            Could not locate any bullets under '## Explicitly not MVP' in \
            \(docURL.path). The parity test depends on that heading; if the \
            doc has been renamed, update extractExplicitlyNotMVPBullets(from:).
            """
        )

        XCTAssertEqual(
            extracted,
            Limitations.notMVP,
            """
            src/ios/PKE/Views/Limitations.swift is out of sync with \
            context/09_mvp_scope.md. \
            Expected (from doc): \(extracted) \
            Got (from app): \(Limitations.notMVP)
            """
        )
    }

    func test_trustBoundariesAreExactlyFourNonEmpty() {
        XCTAssertEqual(Limitations.trustBoundaries.count, 4)
        for (index, caveat) in Limitations.trustBoundaries.enumerated() {
            XCTAssertFalse(
                caveat.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                "Trust boundary \(index) is empty"
            )
        }
    }

    func test_trustBoundariesContainsTheFourCaveatsPinnedByAC2() {
        let required = [
            "no proof of plaintext authenticity",
            "witness independence is informational only",
            "no key rotation in MVP",
            "single-node backend"
        ]
        for caveat in required {
            XCTAssertTrue(
                Limitations.trustBoundaries.contains(caveat),
                "Missing AC#2 trust caveat: \(caveat)"
            )
        }
    }

    // MARK: - Helpers

    /// Walks up from this source file to the repo root and returns the URL
    /// of `context/09_mvp_scope.md`. Path math:
    /// `src/ios/PKETests/UI/LimitationsDocParityTests.swift` → 5 deletions
    /// (file, UI/, PKETests/, ios/, src/) leaves us at the repo root.
    private func mvpScopeDocURL(file: StaticString = #filePath) throws -> URL {
        var url = URL(fileURLWithPath: "\(file)")
        for _ in 0..<5 { url.deleteLastPathComponent() }
        url.appendPathComponent("context")
        url.appendPathComponent("09_mvp_scope.md")
        return url
    }

    /// Extracts every line starting with `- ` from the body of the
    /// `## Explicitly not MVP` section, stopping at the next `## ` heading
    /// or EOF. Strips only the leading `- ` so trailing punctuation in the
    /// doc is preserved (the bullets in the doc end with `,` or `.`).
    private func extractExplicitlyNotMVPBullets(from document: String) -> [String] {
        let lines = document.split(separator: "\n", omittingEmptySubsequences: false)
        var collecting = false
        var bullets: [String] = []
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "## Explicitly not MVP" {
                collecting = true
                continue
            }
            if collecting, trimmed.hasPrefix("## ") {
                break
            }
            if collecting, trimmed.hasPrefix("- ") {
                bullets.append(String(trimmed.dropFirst(2)))
            }
        }
        return bullets
    }
}
