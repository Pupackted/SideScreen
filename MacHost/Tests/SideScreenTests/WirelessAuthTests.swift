import XCTest
@testable import SideScreen

final class WirelessAuthTests: XCTestCase {
    func testTokenIs32Bytes() {
        let token = WirelessAuth.generateToken()
        XCTAssertEqual(token.count, 32)
    }

    func testTwoTokensDiffer() {
        let a = WirelessAuth.generateToken()
        let b = WirelessAuth.generateToken()
        XCTAssertNotEqual(a, b, "Random token collision is astronomically unlikely")
    }

    func testTokenBytesHaveEntropy() {
        let token = WirelessAuth.generateToken()
        let unique = Set(token)
        XCTAssertGreaterThan(unique.count, 15)
    }

    func testPersistAndLoad() {
        let suite = "WirelessAuthTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)

        let original = WirelessAuth.generateToken()
        WirelessAuth.persist(original, store: DefaultsTokenStore(defaults: defaults, key: "t"))
        let loaded = WirelessAuth.load(store: DefaultsTokenStore(defaults: defaults, key: "t"))
        XCTAssertEqual(loaded, original)
    }

    func testLoadOrCreateGeneratesIfMissing() {
        let suite = "WirelessAuthTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)

        let first = WirelessAuth.loadOrCreate(store: DefaultsTokenStore(defaults: defaults, key: "t"))
        let second = WirelessAuth.loadOrCreate(store: DefaultsTokenStore(defaults: defaults, key: "t"))
        XCTAssertEqual(first, second, "loadOrCreate must return the persisted value on second call")
        XCTAssertEqual(first.count, 32)
    }

    func testValidateConstantTime() {
        let token = WirelessAuth.generateToken()
        XCTAssertTrue(WirelessAuth.validate(token, expected: token))
        var bad = token
        bad[0] ^= 0x01
        XCTAssertFalse(WirelessAuth.validate(bad, expected: token))
        XCTAssertFalse(WirelessAuth.validate(Data(repeating: 0, count: 31), expected: token))
    }

    private func freshDefaults() -> UserDefaults {
        let suite = "WirelessAuthTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        return defaults
    }

    func testMigratingStoreMovesLegacyTokenOnce() {
        let primary = DefaultsTokenStore(defaults: freshDefaults(), key: "new")
        let legacy = DefaultsTokenStore(defaults: freshDefaults(), key: "old")
        let token = WirelessAuth.generateToken()
        legacy.write(token)

        let store = MigratingTokenStore(primary: primary, legacy: legacy)
        XCTAssertEqual(store.read(), token)
        XCTAssertEqual(primary.read(), token, "token must land in the primary store")
        XCTAssertNil(legacy.read(), "legacy copy must be wiped after migration")
        XCTAssertEqual(store.read(), token)
    }

    func testMigratingStoreWriteClearsLegacy() {
        let primary = DefaultsTokenStore(defaults: freshDefaults(), key: "new")
        let legacy = DefaultsTokenStore(defaults: freshDefaults(), key: "old")
        legacy.write(WirelessAuth.generateToken())
        let fresh = WirelessAuth.generateToken()
        MigratingTokenStore(primary: primary, legacy: legacy).write(fresh)
        XCTAssertEqual(primary.read(), fresh)
        XCTAssertNil(legacy.read())
    }

    func testResetIssuesNewToken() {
        let store = DefaultsTokenStore(defaults: freshDefaults(), key: "t")
        let first = WirelessAuth.loadOrCreate(store: store)
        let second = WirelessAuth.reset(store: store)
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(WirelessAuth.load(store: store), second)
    }

    func testUsbTokenPushScriptTargetsProtectedReceivers() {
        let token = Data((0..<32).map { UInt8($0) })
        let script = UsbTokenPusher.shellScript(token: token)
        let hex = token.map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(script.contains("--es token \(hex)"))
        XCTAssertTrue(script.contains("-n com.sidescreen.app/com.sidescreen.app.UsbTokenReceiver"))
        XCTAssertTrue(script.contains("-n com.sidescreen.app.debug/com.sidescreen.app.UsbTokenReceiver"))
        XCTAssertTrue(script.hasSuffix("exit\n"))
    }
}
