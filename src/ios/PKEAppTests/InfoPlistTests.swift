import XCTest

// Runs hosted in PKE.app, so `Bundle.main` is the app bundle whose
// Info.plist is built from `PKE/Info.plist` merged with generated keys.
final class InfoPlistTests: XCTestCase {

    private var bonjourServices: [String]? {
        Bundle.main.object(forInfoDictionaryKey: "NSBonjourServices") as? [String]
    }

    func test_bonjourServices_isPresentArray() {
        XCTAssertNotNil(bonjourServices, "NSBonjourServices must be declared as an array")
    }

    func test_bonjourServices_containsTCPWitnessService() {
        XCTAssertEqual(bonjourServices?.contains("_pke-witness._tcp"), true)
    }

    func test_bonjourServices_containsUDPWitnessService() {
        XCTAssertEqual(bonjourServices?.contains("_pke-witness._udp"), true)
    }

    func test_bonjourServices_declaresExactlyTheTwoWitnessServices() {
        XCTAssertEqual(bonjourServices?.sorted(), ["_pke-witness._tcp", "_pke-witness._udp"])
    }

    func test_localNetworkUsageDescription_isPresentAndNonEmpty() {
        let description = Bundle.main.object(
            forInfoDictionaryKey: "NSLocalNetworkUsageDescription"
        ) as? String
        XCTAssertNotNil(description, "NSLocalNetworkUsageDescription must be declared")
        XCTAssertFalse(
            description?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true,
            "NSLocalNetworkUsageDescription must be a non-empty string"
        )
    }
}
