import Foundation
import XCTest
@testable import SideScreen

/// End-to-end checks of the loopback (USB) auth path against a real listener.
final class StreamingServerAuthTests: XCTestCase {
    private var server: StreamingServer!
    private var port: UInt16 = 0
    private let usbToken = AuthSecret.generate()

    override func setUp() async throws {
        server = StreamingServer(port: 0)
        server.expectedUsbToken = usbToken
        try await server.start()
        port = try XCTUnwrap(server.boundPort)
    }

    override func tearDown() async throws {
        server.stop()
        server = nil
    }

    // MARK: - helpers

    /// Blocking loopback TCP client with a receive timeout.
    private final class Client {
        let fd: Int32

        init?(port: UInt16) {
            fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { return nil }
            var tv = timeval(tv_sec: 2, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard rc == 0 else { close(fd); return nil }
        }

        deinit { close(fd) }

        func send(_ data: Data) {
            _ = data.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, data.count, 0) }
        }

        /// Reads up to `count` bytes. Returns what arrived before EOF/timeout,
        /// and whether the peer closed the connection.
        func read(_ count: Int) -> (data: Data, closed: Bool) {
            var out = Data()
            var buf = [UInt8](repeating: 0, count: count)
            while out.count < count {
                let n = recv(fd, &buf, count - out.count, 0)
                if n == 0 { return (out, true) }
                if n < 0 {
                    // A reset (server cancelled before reading) also means closed.
                    let err = errno
                    return (out, err != EAGAIN && err != EWOULDBLOCK)
                }
                out.append(contentsOf: buf[0..<n])
            }
            return (out, false)
        }
    }

    private func handshake(token: Data, name: String = "Test Pad") -> Data {
        let nameBytes = Array(name.utf8)
        return Data(HandshakeCodec.requestMagic) + token + Data([UInt8(nameBytes.count)]) + Data(nameBytes)
    }

    private func okResponse() -> Data { HandshakeCodec.encodeResponse(status: .ok) }

    // MARK: - tests

    func testLoopbackClientWithoutHandshakeIsRejected() throws {
        let client = try XCTUnwrap(Client(port: port))
        // A legacy client starts with capability bytes instead of SSWA.
        client.send(Data(repeating: 8, count: 37 + 4))
        let reply = client.read(64)
        XCTAssertEqual(reply.data, HandshakeCodec.encodeResponse(status: .invalidMagic))
        XCTAssertTrue(client.read(1).closed, "server must close an unauthenticated loopback client")
    }

    func testLoopbackClientWithWrongTokenIsRejected() throws {
        let client = try XCTUnwrap(Client(port: port))
        client.send(handshake(token: AuthSecret.generate()))
        XCTAssertEqual(client.read(5).data, HandshakeCodec.encodeResponse(status: .invalidToken))
        XCTAssertTrue(client.read(1).closed)
    }

    func testLoopbackClientWithTokenIsAccepted() throws {
        let client = try XCTUnwrap(Client(port: port))
        client.send(handshake(token: usbToken))
        XCTAssertEqual(client.read(5).data, okResponse())
    }

    func testLoopbackRejectedWhenNoUsbTokenConfigured() async throws {
        server.stop()
        server = StreamingServer(port: 0)
        try await server.start()
        port = try XCTUnwrap(server.boundPort)
        let client = try XCTUnwrap(Client(port: port))
        client.send(handshake(token: usbToken))
        let reply = client.read(5)
        XCTAssertTrue(reply.data.isEmpty)
        XCTAssertTrue(reply.closed)
    }

    func testCodePairingRefusedOverLoopback() throws {
        server.expectedPairingCode = "12345678"
        let client = try XCTUnwrap(Client(port: port))
        var field = Array("12345678".utf8)
        field += [UInt8](repeating: 0, count: 32 - field.count)
        let name = Array("Pad".utf8)
        client.send(Data(HandshakeCodec.pairingRequestMagic) + Data(field) + Data([UInt8(name.count)]) + Data(name))
        XCTAssertEqual(client.read(5).data, HandshakeCodec.encodeResponse(status: .invalidMagic))
        XCTAssertEqual(server.expectedPairingCode, "12345678", "a loopback attempt must not touch the code")
    }

    func testUnauthenticatedConnectionDoesNotKickActiveSession() throws {
        var disconnects = 0
        let lock = NSLock()
        server.onClientDisconnected = {
            lock.lock(); disconnects += 1; lock.unlock()
        }

        let active = try XCTUnwrap(Client(port: port))
        active.send(handshake(token: usbToken))
        XCTAssertEqual(active.read(5).data, okResponse())

        let intruder = try XCTUnwrap(Client(port: port))
        intruder.send(handshake(token: AuthSecret.generate()))
        XCTAssertEqual(intruder.read(5).data, HandshakeCodec.encodeResponse(status: .invalidToken))

        Thread.sleep(forTimeInterval: 0.3)
        lock.lock(); let count = disconnects; lock.unlock()
        XCTAssertEqual(count, 0, "a failed handshake must not disconnect the active client")
    }
}
