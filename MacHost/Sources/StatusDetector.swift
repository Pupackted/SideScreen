import Foundation
import SystemConfiguration

enum StatusDetector {
    static func adbInstalled() -> Bool {
        return adbExecutablePath() != nil
    }

    static func wifiReachable() -> Bool {
        guard let reach = SCNetworkReachabilityCreateWithName(nil, "1.1.1.1") else { return false }
        var flags = SCNetworkReachabilityFlags()
        guard SCNetworkReachabilityGetFlags(reach, &flags) else { return false }
        return flags.contains(.reachable) && !flags.contains(.connectionRequired)
    }

    // MARK: Quit gate
    // Status polling runs adb in detached tasks. If one of those calls lands
    // after quit-time `adb kill-server`, adb silently starts a new server and
    // it outlives the app again. So on quit we close this gate (new calls bail
    // out) and wait for calls already running before stopping the server.

    private static let gateLock = NSLock()
    private static var shuttingDown = false
    private static var inFlightCalls = 0

    /// Register an adb call. Returns false once quitting has begun: skip the call.
    static func beginAdbCall() -> Bool {
        gateLock.lock(); defer { gateLock.unlock() }
        if shuttingDown { return false }
        inFlightCalls += 1
        return true
    }

    static func endAdbCall() {
        gateLock.lock(); inFlightCalls -= 1; gateLock.unlock()
    }

    /// Close the gate and wait (up to `timeout`) for in-flight adb calls to finish.
    static func beginShutdown(timeout: TimeInterval = 2) {
        gateLock.lock(); shuttingDown = true; gateLock.unlock()
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            gateLock.lock(); let busy = inFlightCalls > 0; gateLock.unlock()
            if !busy { return }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    /// True if an adb client other than the server is running right now, e.g.
    /// an `adb push` from a script or an `adb shell`/logcat in a terminal.
    /// Call after beginShutdown() so our own calls are no longer counted.
    static func otherAdbClientsRunning() -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/ps")
        task.arguments = ["-Ao", "args="]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do { try task.run() } catch { return false }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let lines = String(data: data, encoding: .utf8)?.split(separator: "\n") ?? []
        return lines.contains { line in
            let exe = line.split(separator: " ").first.map(String.init) ?? ""
            return (exe as NSString).lastPathComponent == "adb" && !line.contains("server")
        }
    }

    /// Run `adb devices`, return list of device serials in `device` state.
    /// `duringShutdown` lets quit-time cleanup through the closed gate.
    static func usbDevices(duringShutdown: Bool = false) -> [String] {
        if !duringShutdown {
            guard beginAdbCall() else { return [] }
        }
        defer { if !duringShutdown { endAdbCall() } }
        guard let adbPath = adbExecutablePath() else { return [] }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: adbPath)
        task.arguments = ["devices"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        return output.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: "\t").map(String.init)
            guard parts.count == 2, parts[1] == "device" else { return nil }
            return parts[0]
        }
    }

    /// Heuristic: parse `adb reverse --list` for `tcp:<port> tcp:<port>`.
    /// `serial` targets one device; without it adb refuses as soon as two
    /// devices are attached ("more than one device").
    static func adbReverseConfigured(port: Int, serial: String? = nil) -> Bool {
        guard beginAdbCall() else { return false }
        defer { endAdbCall() }
        guard let adbPath = adbExecutablePath() else { return false }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: adbPath)
        task.arguments = (serial.map { ["-s", $0] } ?? []) + ["reverse", "--list"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            return false
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        return output.contains("tcp:\(port) tcp:\(port)")
    }

    private static var cachedAdbPath: String?
    private static var lastAdbCacheCheck: Date = .distantPast

    static func adbExecutablePath() -> String? {
        // Re-resolve every 5 s so install/uninstall is reflected.
        if let cached = cachedAdbPath, Date().timeIntervalSince(lastAdbCacheCheck) < 5.0 {
            return cached
        }
        let candidatePaths = [
            "/opt/homebrew/bin/adb",
            "/usr/local/bin/adb",
            "\(NSHomeDirectory())/Library/Android/sdk/platform-tools/adb"
        ]
        for path in candidatePaths where FileManager.default.isExecutableFile(atPath: path) {
            cachedAdbPath = path
            lastAdbCacheCheck = Date()
            return path
        }
        // Fallback: ask `which adb` (covers PATH-installed setups).
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        task.arguments = ["adb"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let out = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
               !out.isEmpty,
               FileManager.default.isExecutableFile(atPath: out) {
                cachedAdbPath = out
                lastAdbCacheCheck = Date()
                return out
            }
        } catch {
            // ignore
        }
        cachedAdbPath = nil
        lastAdbCacheCheck = Date()
        return nil
    }

    /// True if an adb server is already listening on its default port.
    /// A plain TCP connect: no adb process is spawned, so this never starts one.
    static func adbServerRunning(port: UInt16 = 5037) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }

    /// Run adb with `arguments`, giving up after `timeout` seconds so a wedged
    /// adb can never hang the caller (used on quit). Returns true on exit 0.
    @discardableResult
    static func runAdb(_ arguments: [String], timeout: TimeInterval = 3) -> Bool {
        guard let adbPath = adbExecutablePath() else { return false }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: adbPath)
        task.arguments = arguments
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        task.terminationHandler = { _ in done.signal() }
        do { try task.run() } catch { return false }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            task.terminate()
            return false
        }
        return task.terminationStatus == 0
    }
}
