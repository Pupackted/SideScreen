import Foundation
import Security

/// Where a 32-byte auth secret lives. Production uses the Keychain; tests use
/// `DefaultsTokenStore` with a throwaway suite.
protocol TokenStore {
    func read() -> Data?
    /// Returns false when the secret could not be stored.
    @discardableResult func write(_ data: Data) -> Bool
    func delete()
}

/// Login-keychain generic password, readable only by this app (default ACL),
/// never synced and only after first unlock.
struct KeychainTokenStore: TokenStore {
    static let service = "com.sidescreen.app.auth"
    let account: String

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
        ]
    }

    func read() -> Data? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            if status != errSecItemNotFound {
                debugLog("Keychain read failed for \(account): \(status)")
            }
            return nil
        }
        return result as? Data
    }

    @discardableResult
    func write(_ data: Data) -> Bool {
        let update: [String: Any] = [kSecValueData as String: data]
        var status = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = baseQuery
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        if status != errSecSuccess {
            debugLog("Keychain write failed for \(account): \(status)")
            return false
        }
        return true
    }

    func delete() {
        SecItemDelete(baseQuery as CFDictionary)
    }
}

/// Plain UserDefaults storage. Only used as the legacy location to migrate
/// from, and by tests.
struct DefaultsTokenStore: TokenStore {
    let defaults: UserDefaults
    let key: String

    func read() -> Data? { defaults.data(forKey: key) }

    @discardableResult
    func write(_ data: Data) -> Bool {
        defaults.set(data, forKey: key)
        return true
    }

    func delete() { defaults.removeObject(forKey: key) }
}

/// Reads from `primary`; if it is empty but `legacy` has a secret, moves it to
/// `primary` once and wipes the legacy copy. Writes always go to `primary`.
struct MigratingTokenStore: TokenStore {
    let primary: TokenStore
    let legacy: TokenStore

    func read() -> Data? {
        if let current = primary.read() { return current }
        guard let old = legacy.read() else { return nil }
        if primary.write(old), primary.read() == old {
            legacy.delete()
        }
        return old
    }

    @discardableResult
    func write(_ data: Data) -> Bool {
        let ok = primary.write(data)
        if ok { legacy.delete() }
        return ok
    }

    func delete() {
        primary.delete()
        legacy.delete()
    }
}

/// Shared helpers for the 32-byte secrets (wireless + USB).
enum AuthSecret {
    static func generate() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return Data(bytes)
    }

    static func loadOrCreate(store: TokenStore) -> Data {
        if let existing = store.read(), existing.count == 32 {
            return existing
        }
        let fresh = generate()
        if !store.write(fresh) {
            // Still usable for this run; the tablet just has to re-pair next launch.
            debugLog("Auth secret could not be persisted — using an in-memory one for this run")
        }
        return fresh
    }

    /// Constant-time compare.
    static func validate(_ candidate: Data, expected: Data) -> Bool {
        guard candidate.count == expected.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<expected.count {
            diff |= candidate[i] ^ expected[i]
        }
        return diff == 0
    }
}
