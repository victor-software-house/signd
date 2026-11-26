import AgentProtocol
@testable import AgentServer
import CryptoKit
import Darwin
import Foundation
import KeyStore
import NIOCore
import Synchronization
import SSHEncoding
import Testing

/// An in-memory store, for tests on runners that lack a Secure Enclave and signd's entitlements.
final class MemoryStore: KeyStorage {
    private let keys = Mutex<[StoredKey]>([])

    func list() throws(StoreError) -> [StoredKey] { keys.withLock { $0 } }

    func add(_ key: StoredKey) throws(StoreError) {
        try keys.withLock { keys throws(StoreError) in
            if keys.contains(where: { $0.name == key.name }) { throw .duplicate(key.name) }
            keys.append(key)
        }
    }

    func replace(_ key: StoredKey) throws(StoreError) {
        try keys.withLock { keys throws(StoreError) in
            guard let index = keys.firstIndex(where: { $0.name == key.name }) else { throw .notFound(key.name) }
            keys[index] = key
        }
    }

    func delete(name: String) throws(StoreError) {
        try keys.withLock { keys throws(StoreError) in
            guard keys.contains(where: { $0.name == name }) else { throw .notFound(name) }
            keys.removeAll { $0.name == name }
        }
    }
}

/// A stored key whose `keyData` is an Ed25519 seed, opened by `softwareOpener` in place of the Secure Enclave.
func storedSoftwareKey(_ name: String) -> StoredKey {
    let key = Curve25519.Signing.PrivateKey()
    let publicKey = PublicKey.ed25519(key.publicKey.rawRepresentation)
    return StoredKey(name: name, kind: .secureEnclave, publicBlob: publicKey.blob, comment: "", hosts: [], keyData: key.rawRepresentation)
}

let softwareOpener: Agent.Opener = { key throws(SignError) in
    guard case let .ed25519(publicKey)? = key.publicKey else { throw .invalidKey("test keys are Ed25519") }
    return try SoftwareSigner(.ed25519(seed: key.keyData, publicKey: publicKey))
}

func makeAgent(_ store: MemoryStore, lifetime: TimeInterval = 3600) async -> Agent {
    let agent = Agent(store: store, version: "test", lifetime: { lifetime }, opener: softwareOpener)
    await agent.reload()
    return agent
}

func memoryKey() -> PrivateKey {
    let key = Curve25519.Signing.PrivateKey()
    return .ed25519(seed: key.rawRepresentation, publicKey: key.publicKey.rawRepresentation)
}

@Suite struct AgentState {
    @Test func listsStoredAndMemoryOnlyKeys() async throws {
        let store = MemoryStore()
        try store.add(storedSoftwareKey("stored"))
        let agent = await makeAgent(store)
        #expect(await agent.add(memoryKey(), comment: "added", constraints: Constraints()) == .success)
        #expect(await agent.identities().map(\.comment) == ["stored", "added"])
    }

    @Test func aLifetimeConstraintDropsTheKey() async {
        let agent = await makeAgent(MemoryStore())
        _ = await agent.add(memoryKey(), comment: "brief", constraints: Constraints(lifetime: 2))
        await agent.dropExpired(now: Date().addingTimeInterval(3))
        #expect(await agent.identities().isEmpty)
    }

    @Test func confirmAndExtensionConstraintsAreRefused() async {
        let agent = await makeAgent(MemoryStore())
        #expect(await agent.add(memoryKey(), comment: "", constraints: Constraints(requiresConfirmation: true)) == .failure)
        #expect(await agent.add(memoryKey(), comment: "", constraints: Constraints(extensions: ["x@example.com"])) == .failure)
        #expect(await agent.identities().isEmpty)
    }

    @Test func removeAllKeepsStoredKeys() async throws {
        let store = MemoryStore()
        let stored = storedSoftwareKey("stored")
        try store.add(stored)
        let agent = await makeAgent(store)
        _ = await agent.add(memoryKey(), comment: "added", constraints: Constraints())
        #expect(await agent.removeAll() == .success)
        #expect(await agent.remove(blob: stored.publicBlob) == .failure)
        #expect(await agent.identities().map(\.comment) == ["stored"])
    }

    @Test func anOpenKeyLeavesMemoryAfterItsLifetime() async throws {
        let store = MemoryStore()
        let stored = storedSoftwareKey("stored")
        try store.add(stored)
        let agent = await makeAgent(store, lifetime: 1)
        #expect(await agent.signer(for: stored.publicBlob) != nil)
        #expect(await agent.status().keys.first?.isInMemory == true)
        await agent.dropExpired(now: Date().addingTimeInterval(2))
        #expect(await agent.status().keys.first?.isInMemory == false)
    }

    @Test func aKeyAddedToTheStoreIsFoundOnFirstSign() async throws {
        let store = MemoryStore()
        let agent = await makeAgent(store)
        let stored = storedSoftwareKey("later")
        try store.add(stored)
        #expect(await agent.signer(for: stored.publicBlob) != nil)
    }
}

/// Signs only once released, standing in for a Secure Enclave call that is still running.
final class GatedSigner: Signer {
    let publicKey = PublicKey.ed25519(Data(repeating: 5, count: 32))
    private let gate = DispatchSemaphore(value: 0)
    private let entered: AsyncStream<Void>.Continuation

    init(entered: AsyncStream<Void>.Continuation) { self.entered = entered }

    func sign(_: Data, flags _: SignFlags) throws(SignError) -> Signature {
        entered.yield()
        gate.wait()
        return Signature(algorithm: "ssh-ed25519", bytes: Data(repeating: 0, count: 64))
    }

    func release(_ count: Int) {
        for _ in 0..<count { gate.signal() }
    }
}

@Suite struct Concurrency {
    /// Every signature waits for the release at the end, so the list request
    /// returns only if no signature in flight delays it. If one does, the time
    /// limit fails the test. No clock is read: a time bound fails on a busy
    /// runner whatever the agent does.
    @Test(.timeLimit(.minutes(1))) func signaturesInFlightDoNotDelayAListRequest() async throws {
        let store = MemoryStore()
        let stored = storedSoftwareKey("slow")
        try store.add(stored)
        let (entered, continuation) = AsyncStream<Void>.makeStream()
        let signer = GatedSigner(entered: continuation)
        let agent = Agent(store: store, version: "test", lifetime: { 3600 }, opener: { _ throws(SignError) in signer })
        await agent.reload()
        let server = Server(agent: agent)
        let count = 8
        try await withThrowingTaskGroup { group in
            // Whatever ends the test, the signatures are let go: they wait on the
            // shared thread pool, and one left waiting would stall other tests.
            defer { signer.release(count) }
            for _ in 0..<count {
                group.addTask {
                    guard case .signature = await server.respond(to: .sign(keyBlob: stored.publicBlob, data: Data([1]), flags: [])) else {
                        // No signature started, so nothing else would end the wait below.
                        continuation.finish()
                        throw SignError.failed("no signature")
                    }
                }
            }
            var signing = entered.makeAsyncIterator()
            _ = await signing.next()
            // A list request that waits on a signature ends only at the time limit,
            // whose cancellation lets the signatures go, so the request returns.
            await withTaskCancellationHandler {
                _ = await server.respond(to: .identities)
            } onCancel: {
                signer.release(count)
            }
            signer.release(count)
            try await group.waitForAll()
        }
    }
}

/// A wrapped Ed25519 key, sealed to `agreement` in place of a Secure Enclave key.
func storedWrappedKey(_ name: String, to agreement: P256.KeyAgreement.PrivateKey) throws -> StoredKey {
    let key = try KeyImport.generate(.ed25519)
    let wrapped = try Wrapping.seal(key, comment: name, to: agreement.publicKey)
    return StoredKey(name: name, kind: .wrapped, publicBlob: key.publicKey.blob, comment: name, hosts: [], source: "test", keyData: Data(), wrapped: wrapped)
}

/// Opens wrapped keys with `agreement`, as `Agent.openStored` does with the Secure Enclave key.
func wrappedOpener(_ agreement: P256.KeyAgreement.PrivateKey) -> Agent.Opener {
    { key throws(SignError) in
        guard let wrapped = key.wrapped else { throw .invalidKey("no wrapped key") }
        do {
            return try SoftwareSigner(try Wrapping.open(wrapped, publicBlob: key.publicBlob, with: agreement).0)
        } catch let error as SignError {
            throw error
        } catch {
            throw .invalidKey("\(error)")
        }
    }
}

@Suite struct WrappedKeys {
    @Test func aWrappedKeySigns() async throws {
        let agreement = P256.KeyAgreement.PrivateKey()
        let store = MemoryStore()
        let stored = try storedWrappedKey("wrapped", to: agreement)
        try store.add(stored)
        let agent = Agent(store: store, version: "test", lifetime: { 3600 }, opener: wrappedOpener(agreement))
        await agent.reload()
        let signer = try #require(await agent.signer(for: stored.publicBlob))
        guard case let .ed25519(publicKey)? = stored.publicKey else {
            Issue.record("not Ed25519")
            return
        }
        let signature = try signer.sign(Data("data".utf8), flags: [])
        #expect(try Curve25519.Signing.PublicKey(rawRepresentation: publicKey).isValidSignature(signature.bytes, for: Data("data".utf8)))
    }

    @Test func aTamperedKeyFailsOnceThenLeavesTheList() async throws {
        let agreement = P256.KeyAgreement.PrivateKey()
        let store = MemoryStore()
        var tampered = try storedWrappedKey("tampered", to: agreement)
        let intact = try storedWrappedKey("intact", to: agreement)
        tampered.wrapped?.ciphertext = try #require(intact.wrapped?.ciphertext)
        try store.add(tampered)
        try store.add(intact)
        let agent = Agent(store: store, version: "test", lifetime: { 3600 }, opener: wrappedOpener(agreement))
        await agent.reload()
        #expect(await agent.identities().count == 2)

        #expect(await agent.signer(for: tampered.publicBlob) == nil)
        #expect(await agent.identities().map(\.comment) == ["intact"])
        #expect(await agent.status().keys.map(\.name) == ["intact"])
        #expect(await agent.signer(for: intact.publicBlob) != nil)

        await agent.reload()
        #expect(await agent.identities().count == 2)
    }
}

/// Sends sign requests over a real Unix socket from one connection and times each reply.
private func timeSignatures(socketPath: String, blob: Data, count: Int) -> [Duration] {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    defer { close(fd) }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(socketPath.utf8)) }
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    guard connected == 0 else { return [] }

    var body = Data([MessageType.signRequest.rawValue])
    body.appendString(blob)
    body.appendString(Data("data".utf8))
    body.appendUInt32(0)
    var request = Data()
    request.appendString(body)

    func readAll(_ count: Int) -> Data? {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: count)
        while data.count < count {
            let n = read(fd, &buffer, count - data.count)
            guard n > 0 else { return nil }
            data.append(contentsOf: buffer[0..<n])
        }
        return data
    }

    var durations: [Duration] = []
    for _ in 0..<count {
        let start = ContinuousClock.now
        guard request.withUnsafeBytes({ write(fd, $0.baseAddress, $0.count) }) == request.count,
              let header = readAll(4), let reply = readAll(header.reduce(0) { $0 << 8 | Int($1) }),
              reply.first == MessageType.signResponse.rawValue else { return durations }
        durations.append(ContinuousClock.now - start)
    }
    return durations
}

@Suite struct WarmSignatures {
    @Test func aWrappedKeySignsFastOnceOpen() async throws {
        let agreement = P256.KeyAgreement.PrivateKey()
        let store = MemoryStore()
        let stored = try storedWrappedKey("warm", to: agreement)
        try store.add(stored)
        let agent = Agent(store: store, version: "test", lifetime: { 3600 }, opener: wrappedOpener(agreement))
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("warm-\(UUID().uuidString.prefix(6))")
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("agent").path
        let server = Task { try await Server(agent: agent).run(socketPath: path) }
        defer { server.cancel() }
        for _ in 0..<100 where !FileManager.default.fileExists(atPath: path) { try await Task.sleep(for: .milliseconds(50)) }

        let blob = stored.publicBlob
        let durations = await withCheckedContinuation { continuation in
            DispatchQueue.global().async { continuation.resume(returning: timeSignatures(socketPath: path, blob: blob, count: 1000)) }
        }

        #expect(durations.count == 1000)
        let warm = durations.dropFirst().sorted()
        let median = try #require(warm.isEmpty ? nil : warm[warm.count / 2])
        print("WARM p50", median)
        #expect(median < .milliseconds(1), "p50 was \(median)")
    }
}

/// Connects to the agent's Unix socket and returns the descriptor, or nil when the connection fails.
private func connectToAgent(socketPath: String) -> Int32? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(socketPath.utf8)) }
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    guard connected == 0 else {
        close(fd)
        return nil
    }
    return fd
}

/// The number of descriptors this process has open.
private func openDescriptorCount() -> Int {
    (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? 0
}

/// Asks for the identities over a real Unix socket and returns the type of the reply, or nil when the agent does not answer.
private func identitiesReplyType(socketPath: String) -> UInt8? {
    guard let fd = connectToAgent(socketPath: socketPath) else { return nil }
    defer { close(fd) }

    var request = Data()
    request.appendString(Data([MessageType.requestIdentities.rawValue]))
    guard request.withUnsafeBytes({ write(fd, $0.baseAddress, $0.count) }) == request.count else { return nil }

    func readAll(_ count: Int) -> Data? {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: count)
        while data.count < count {
            let n = read(fd, &buffer, count - data.count)
            guard n > 0 else { return nil }
            data.append(contentsOf: buffer[0..<n])
        }
        return data
    }
    guard let header = readAll(4), let reply = readAll(header.reduce(0) { $0 << 8 | Int($1) }) else { return nil }
    return reply.first
}

@Suite struct AcceptErrors {
    @Test(.timeLimit(.minutes(1))) func theServerKeepsAcceptingAfterAFailedFcntl() async throws {
        let agent = await makeAgent(MemoryStore())
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("accept-\(UUID().uuidString.prefix(6))")
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("agent").path
        let (listening, announce) = AsyncStream.makeStream(of: (any Channel).self)
        let server = Task { try await Server(agent: agent).listen(socketPath: path) { announce.yield($0) } }
        defer { server.cancel() }
        let channel = try #require(await listening.first { _ in true })

        try await Server.failAccept(on: channel)

        let reply = await withCheckedContinuation { continuation in
            DispatchQueue.global().async { continuation.resume(returning: identitiesReplyType(socketPath: path)) }
        }
        #expect(reply == MessageType.identitiesAnswer.rawValue)
    }

    @Test(.timeLimit(.minutes(1))) func theServerKeepsAcceptingAndReleasesClientsThatCloseAtOnce() async throws {
        let agent = await makeAgent(MemoryStore())
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("accept-\(UUID().uuidString.prefix(6))")
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("agent").path
        let (listening, announce) = AsyncStream.makeStream(of: (any Channel).self)
        let server = Task { try await Server(agent: agent).listen(socketPath: path) { announce.yield($0) } }
        defer { server.cancel() }
        _ = try #require(await listening.first { _ in true })

        let before = openDescriptorCount()
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                DispatchQueue.concurrentPerform(iterations: 2000) { _ in
                    if let fd = connectToAgent(socketPath: path) { close(fd) }
                }
                continuation.resume()
            }
        }

        // The server closes each dropped connection on its event loop, after the clients are gone.
        let margin = 16
        var after = openDescriptorCount()
        for _ in 0..<100 where after > before + margin {
            try await Task.sleep(for: .milliseconds(100))
            after = openDescriptorCount()
        }
        #expect(after <= before + margin, "\(before) descriptors were open before the clients, \(after) after")

        let reply = await withCheckedContinuation { continuation in
            DispatchQueue.global().async { continuation.resume(returning: identitiesReplyType(socketPath: path)) }
        }
        #expect(reply == MessageType.identitiesAnswer.rawValue)
    }
}
