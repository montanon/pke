import XCTest
@testable import PKECrypto

// Placeholder retained so the existing test target keeps a discoverable entry
// point; real coverage lives in JSONValueTests, CanonicalJSONTests, Base64URLTests.
final class PKECryptoTests: XCTestCase {
    func testNamespaceExists() {
        _ = PKECrypto.self
    }
}
