import Foundation

/// Delivers the USB auth token to the Side Screen app on a tablet over adb.
///
/// The token goes to `UsbTokenReceiver`, which is protected by
/// `android.permission.DUMP`: only the adb shell and the system hold it, so
/// other apps on the tablet can neither read nor forge the token. The command
/// is written to `adb shell`'s stdin rather than passed as arguments, so the
/// token never shows up in this Mac's process list.
enum UsbTokenPusher {
    static let action = "com.sidescreen.app.SET_USB_TOKEN"
    /// Release and debug (`.debug` suffix) builds of the Android app.
    static let receivers = [
        "com.sidescreen.app/com.sidescreen.app.UsbTokenReceiver",
        "com.sidescreen.app.debug/com.sidescreen.app.UsbTokenReceiver",
    ]

    static func shellScript(token: Data) -> String {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        // -f 32 = FLAG_INCLUDE_STOPPED_PACKAGES, so it also lands right after install.
        let lines = receivers.map {
            "am broadcast -f 32 -a \(action) -n \($0) --es token \(hex) >/dev/null 2>&1"
        }
        return (lines + ["exit"]).joined(separator: "\n") + "\n"
    }

    @discardableResult
    static func push(adbPath: String, serial: String, token: Data) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: adbPath)
        process.arguments = ["-s", serial, "shell"]
        let stdin = Pipe()
        let output = Pipe()
        process.standardInput = stdin
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
            stdin.fileHandleForWriting.write(Data(shellScript(token: token).utf8))
            try? stdin.fileHandleForWriting.close()
            process.waitUntilExit()
            _ = output.fileHandleForReading.readDataToEndOfFile()
            let ok = process.terminationStatus == 0
            debugLog(ok ? "🔑 USB token delivered to \(serial)" : "⚠️ USB token push to \(serial) exited \(process.terminationStatus)")
            return ok
        } catch {
            debugLog("⚠️ USB token push to \(serial) failed: \(error.localizedDescription)")
            return false
        }
    }
}
