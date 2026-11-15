# Side Screen: security review (15 Nov 2026)

Reviewed upstream `tranvuongquocdat/SideScreen` at commit `73b8067` (7 Nov 2026, v1.1.1). Mac host is Swift (~6.8k lines); the Android client is Kotlin.

## Verdict

Nothing malicious found. I checked for:

- **Tracking:** no telemetry, analytics, ads or tracking SDKs.
- **Network traffic:** the code reaches only GitHub (updates and links), sidescreen.dev and the Play Store.
- **Hidden code:** no hidden downloads, no obfuscation, no shell piping.
- **Dependencies:** all standard. Mac uses Sparkle. Android uses AndroidX, CameraX, ML Kit barcode, and Play update/review.
- **Gradle wrapper jar:** its sha256 `a8451eed…` is on Gradle's official checksum list.
- **Command execution:** shell use is limited to running `adb devices` / `adb reverse` and restarting the app itself.
- **Wireless pairing:** well built. It uses a 32-byte random token, constant-time compares, and a one-time 8-digit code with a 5-attempt limit. Non-USB clients are refused unless wireless mode is on.

## Risks worth fixing in our fork (bugs, not malice)

1. **USB mode has no authentication** (`StreamingServer.swift`, `onConnectionReady`). Loopback clients skip auth.
   - USB works via `adb reverse`, which opens the port on the tablet's localhost.
   - So any app on the tablet, or any process on the Mac, can connect to it, watch the Mac screen and send clicks to the Mac.
   - Fix: require the token on loopback too, sending it to the tablet once over adb.
2. **Any new connection kicks the current one before auth** (`handleConnection`). In wireless mode, anyone on the same Wi-Fi can keep disconnecting you. Fix: only replace the session after the new client authenticates.
3. **Wireless stream and token are unencrypted** (plain TCP, no TLS).
   - On shared or public Wi-Fi, someone sniffing can see the screen and steal the token. Fine on a trusted home network.
   - Fix: TLS, or a Noise-style handshake keyed from the QR token.
4. **Weakened hardened runtime**: `disable-library-validation` and `allow-unsigned-executable-memory` in `SideScreen.entitlements`.
   - The app holds Screen Recording and Accessibility permissions, so this makes code injection by other malware easier.
   - Fix: remove both and check nothing breaks.
5. **Auto-update (Sparkle) pulls from the upstream GitHub.** It's signed with EdDSA, so it's safe-ish, but the upstream dev can push new code to us. Fix: point `SUFeedURL`/`SUPublicEDKey` at our own releases, or turn off automatic checks.
6. The wireless token is stored in plain `UserDefaults` (any process running as the user can read it). Fix: move it to the Keychain.
7. It uses the private `CGVirtualDisplay` API, which is normal for this kind of app (BetterDisplay does the same) but may break on macOS updates.

## Fix status (branch `security-hardening`, 15 Nov 2026)

| # | Issue | Status |
|---|---|---|
| 1 | USB mode unauthenticated | **Fixed.** USB clients now run the same SSWA token handshake as wireless.<br>• The Mac keeps a separate USB token in the Keychain (`UsbAuth`) and delivers it over adb on every startup and replug (`UsbTokenPusher`). The token goes through `adb shell` stdin, so it never appears in `ps`.<br>• On the tablet, `UsbTokenReceiver` is guarded by `android.permission.DUMP` (adb shell or system only) and stores the token in `noBackupFilesDir`.<br>• Code pairing is refused on the loopback path. |
| 2 | New connections kick the active session pre-auth | **Fixed.** Connections stay candidates until they authenticate (`promote`). Unauthenticated candidates are dropped after 5 s, and a replaced connection's pending read can no longer touch the new session. |
| 3 | Wireless stream unencrypted | **Not fixed yet.** Needs TLS-PSK or a Noise handshake on both sides. Use wireless only on trusted Wi-Fi, or use USB. |
| 4 | Weakened hardened runtime | **Fixed.**<br>• `allow-unsigned-executable-memory` is removed everywhere.<br>• `disable-library-validation` now applies only to ad-hoc builds (`SideScreen.adhoc.entitlements`). Ad-hoc signatures have no Team ID, so Sparkle.framework can't load otherwise.<br>• Builds signed with a real identity use `SideScreen.entitlements` with no exemptions. Build with `SIDESCREEN_SIGN_IDENTITY="Apple Development: …"`. |
| 5 | Auto-update from upstream | **Fixed.** `SUFeedURL`/`SUPublicEDKey` removed from `Info.plist` and `build_mac.sh`, so Sparkle stays off (`AppUpdater` already skips startup without a feed). |
| 6 | Token in plain UserDefaults | **Fixed.** Tokens live in the Keychain (`KeychainTokenStore`). The old UserDefaults token is migrated once and wiped. |

Verification:
- Mac: `swift test` passes all 95 tests (85 existing + 10 new). The new ones include end-to-end loopback auth tests in `StreamingServerAuthTests`. The two profile-hold tests now authenticate first.
- App: built with `scripts/build_mac.sh`, signed with an Apple Development identity, and launches under full hardened runtime.
- Android: `testDebugUnitTest` passes (45 tests) and `assembleDebug` builds.
- **Not yet tested end to end on a real tablet.**

Compatibility: the Play Store / upstream Android app can no longer connect over USB to this Mac build, because it doesn't send the token. Install the fork's Android build (debug id `com.sidescreen.app.debug`).
