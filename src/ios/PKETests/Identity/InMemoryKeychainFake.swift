// In-memory KeychainProtocol fake for `DeviceIdentityServiceTests`.
//
// Lets tests preload state, snapshot writes, and inject failures keyed by
// label + operation. Mirrors the production wrapper's three-method surface;
// nothing here ever touches `SecItem*`, so the suite runs on macOS CI
// without entitlements or a real Keychain.

#if canImport(Security)
import Foundation
@testable import PKEIdentity
import PKECrypto

final class InMemoryKeychainFake: KeychainProtocol, @unchecked Sendable {
    enum Operation {
        case set
        case get
        case delete
    }

    struct FailureKey: Hashable {
        let label: String
        let operation: Operation
    }

    private let lock = NSLock()
    private var storage: [String: Data] = [:]
    private var failures: [FailureKey: CryptoError] = [:]

    private(set) var setCalls: [(label: String, data: Data)] = []
    private(set) var getCalls: [String] = []
    private(set) var deleteCalls: [String] = []

    init(preloaded: [String: Data] = [:]) {
        self.storage = preloaded
    }

    func preload(_ data: Data, for label: String) {
        lock.lock()
        defer { lock.unlock() }
        storage[label] = data
    }

    func failNext(_ operation: Operation, for label: String, with error: CryptoError) {
        lock.lock()
        defer { lock.unlock() }
        failures[FailureKey(label: label, operation: operation)] = error
    }

    func snapshot() -> [String: Data] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func set(label: String, data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        setCalls.append((label, data))
        if let error = failures.removeValue(forKey: FailureKey(label: label, operation: .set)) {
            throw error
        }
        storage[label] = data
    }

    func get(label: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        getCalls.append(label)
        if let error = failures.removeValue(forKey: FailureKey(label: label, operation: .get)) {
            throw error
        }
        return storage[label]
    }

    func delete(label: String) throws {
        lock.lock()
        defer { lock.unlock() }
        deleteCalls.append(label)
        if let error = failures.removeValue(forKey: FailureKey(label: label, operation: .delete)) {
            throw error
        }
        storage.removeValue(forKey: label)
    }
}
#endif
