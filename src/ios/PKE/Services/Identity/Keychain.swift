// Minimal Keychain wrapper backing PKEIdentity. Every write pins
// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and
// `kSecAttrSynchronizable = false` so key material never syncs off-device.
// Non-success `OSStatus` values surface as `CryptoError.keychain(reason:)`;
// `errSecItemNotFound` on read is treated as absence, not error.
//
// Items are stored under `kSecClassGenericPassword` keyed by `kSecAttrAccount`
// (the caller-supplied label) within a fixed `kSecAttrService` namespace, so
// the wrapper never collides with other consumers on the device.

#if canImport(Security)
import Foundation
import PKECrypto
import Security

public protocol KeychainProtocol {
    func set(label: String, data: Data) throws
    func get(label: String) throws -> Data?
    func delete(label: String) throws
}

public struct Keychain: KeychainProtocol {

    /// Service namespace shared by every PKE identity item.
    public static let service = "com.pke.identity"

    public init() {}

    public func set(label: String, data: Data) throws {
        let attributes: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: label,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            kSecUseDataProtectionKeychain: kCFBooleanTrue as Any,
            kSecValueData: data
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.keychain(reason: "SecItemAdd OSStatus \(status)")
        }
    }

    public func get(label: String) throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: label,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            kSecUseDataProtectionKeychain: kCFBooleanTrue as Any,
            kSecReturnData: kCFBooleanTrue as Any,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw CryptoError.keychain(reason: "SecItemCopyMatching returned non-Data payload")
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw CryptoError.keychain(reason: "SecItemCopyMatching OSStatus \(status)")
        }
    }

    public func delete(label: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: label,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            kSecUseDataProtectionKeychain: kCFBooleanTrue as Any
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CryptoError.keychain(reason: "SecItemDelete OSStatus \(status)")
        }
    }
}
#endif
