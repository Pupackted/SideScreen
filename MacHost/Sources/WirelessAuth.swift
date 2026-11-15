import Foundation

/// Token a tablet must present over WiFi (embedded in the pairing QR).
/// Stored in the Keychain; older builds kept it in UserDefaults, which is
/// migrated on first read.
enum WirelessAuth {
    static let userDefaultsKey = "wireless.authToken"

    static var defaultStore: TokenStore {
        MigratingTokenStore(
            primary: KeychainTokenStore(account: userDefaultsKey),
            legacy: DefaultsTokenStore(defaults: .standard, key: userDefaultsKey)
        )
    }

    static func generateToken() -> Data { AuthSecret.generate() }

    static func persist(_ token: Data, store: TokenStore = defaultStore) {
        store.write(token)
    }

    static func load(store: TokenStore = defaultStore) -> Data? {
        store.read()
    }

    static func loadOrCreate(store: TokenStore = defaultStore) -> Data {
        AuthSecret.loadOrCreate(store: store)
    }

    @discardableResult
    static func reset(store: TokenStore = defaultStore) -> Data {
        store.delete()
        return loadOrCreate(store: store)
    }

    static func validate(_ candidate: Data, expected: Data) -> Bool {
        AuthSecret.validate(candidate, expected: expected)
    }
}

/// Token a tablet must present over USB (adb reverse → loopback). Without it,
/// any app on the tablet — or any process on this Mac — could open the
/// loopback port, watch the screen and inject clicks. The Mac hands it to the
/// Side Screen app over adb (`UsbTokenPusher`), never over the network.
enum UsbAuth {
    static let account = "usb.authToken"

    static var defaultStore: TokenStore { KeychainTokenStore(account: account) }

    static func loadOrCreate(store: TokenStore = defaultStore) -> Data {
        AuthSecret.loadOrCreate(store: store)
    }
}
