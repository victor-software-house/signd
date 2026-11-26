import AgentProtocol
import Backup
import Darwin
import Foundation
import KeyStore
import NIOCore
import NIOFoundationCompat
import NIOPosix
import os
import SSHEncoding
import Sync
import Synchronization

/// signd's own extensions, for its command line.
public enum PrivateExtension {
    public static let status = "signd-status@victor-software-house.com"
    public static let reload = "signd-reload@victor-software-house.com"
    /// Runs a check of iCloud now and answers with its `CheckSummary` as JSON.
    public static let sync = "signd-sync@victor-software-house.com"
    /// Answers with the sync state as JSON.
    public static let syncState = "signd-sync-state@victor-software-house.com"
    /// Shares the key its contents name, and answers with a `SyncResult` as JSON.
    public static let share = "signd-share@victor-software-house.com"
    /// Deletes the shared key its contents name on every device, and answers with a `SyncResult` as JSON.
    public static let deleteShared = "signd-delete-shared@victor-software-house.com"
    /// Answers with the devices of the account as JSON.
    public static let devices = "signd-devices@victor-software-house.com"
    /// Removes the device its contents name, and answers with a `SyncResult` as JSON.
    public static let removeDevice = "signd-remove-device@victor-software-house.com"
    /// Stores the backup token its contents carry, with the vault, on every Mac, and answers with a `SyncResult` as JSON.
    public static let backupLogin = "signd-backup-login@victor-software-house.com"
    /// Deletes the backup token on every Mac, and answers with a `SyncResult` as JSON.
    public static let backupLogout = "signd-backup-logout@victor-software-house.com"
    /// Lists the backup's keys, or restores the ones its contents name; answers with a `BackupRestoreList` or a `BackupRestoreResult` as JSON.
    public static let backupRestore = "signd-backup-restore@victor-software-house.com"
    /// Answers with the backup's `BackupStatus` as JSON.
    public static let backupStatus = "signd-backup-status@victor-software-house.com"

    /// Every extension of signd's command line; a connection that the SSH client forwarded may use none of them.
    static let all: Set<String> = [status, reload, sync, syncState, share, deleteShared, devices, removeDevice, backupLogin, backupLogout, backupRestore, backupStatus]
}

/// What a backup login carries to the agent: the token, as JSON in the extension's one string argument.
public struct BackupLoginRequest: Codable, Sendable {
    public let token: String
    public let vault: String

    public init(token: String, vault: String) {
        self.token = token
        self.vault = vault
    }
}

/// What a backup restore carries to the agent: the keys to restore, or with `listOnly` a request for the backup's keys.
public struct BackupRestoreRequest: Codable, Sendable {
    public let names: [String]
    public let all: Bool
    public let local: Bool
    public let listOnly: Bool

    public init(names: [String], all: Bool, local: Bool, listOnly: Bool) {
        self.names = names
        self.all = all
        self.local = local
        self.listOnly = listOnly
    }
}

/// The backup commands the agent answers; the agent is the only process that calls CloudKit and 1Password.
public protocol BackupCommands: Sendable {
    func logIn(token: String, vault: String) async -> SyncResult
    func logOut() async -> SyncResult
    func restore(names: [String], all: Bool, local: Bool) async -> BackupRestoreResult
    func list() async -> BackupRestoreList
    func status() async -> BackupStatus
}

/// A file by its device and inode, so two paths to one file match.
struct FileIdentity: Equatable, Sendable {
    let device: dev_t
    let inode: ino_t

    init?(path: String) {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        device = info.st_dev
        inode = info.st_ino
    }

    /// The executable file process `pid` runs, or nil when it cannot be read.
    init?(executableOf pid: pid_t) {
        // PROC_PIDPATHINFO_MAXSIZE is 4 * MAXPATHLEN.
        var buffer = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        self.init(path: String(decoding: buffer.prefix(Int(length)), as: UTF8.self))
    }
}

/// What the agent knows about one connection.
final class Connection: Sendable {
    /// The process on the other end, from `LOCAL_PEERPID`.
    let peerPID: pid_t?
    private let forwarded = Mutex(false)

    init(peerPID: pid_t?) { self.peerPID = peerPID }

    var isForwarded: Bool { forwarded.withLock { $0 } }

    func markForwarded() { forwarded.withLock { $0 = true } }
}

/// Splits the byte stream into message bodies by their 4-byte length.
struct FrameDecoder: ByteToMessageDecoder {
    typealias InboundOut = ByteBuffer

    struct TooLong: Error {}

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let length = buffer.getInteger(at: buffer.readerIndex, as: UInt32.self) else { return .needMoreData }
        guard length <= Frame.maximumLength else { throw TooLong() }
        guard buffer.readableBytes >= 4 + Int(length) else { return .needMoreData }
        buffer.moveReaderIndex(forwardBy: 4)
        context.fireChannelRead(wrapInboundOut(buffer.readSlice(length: Int(length))!))
        return .continue
    }
}

/// Drops the accept error that SwiftNIO reports through the server channel's pipeline and survives.
///
/// On Darwin, `fcntl` on an accepted socket fails with an invalid argument error (EINVAL) when the client has already closed it.
/// SwiftNIO reports `NIOFcntlFailedError` and keeps the server channel open.
/// The reports are [ServerSocketChannel behaves non-sensical if fcntl on accepted socket returns EINVAL](https://github.com/apple/swift-nio/issues/1030)
/// and [Recover from EINVAL even if the error is untyped](https://github.com/apple/swift-nio/issues/1598).
///
/// The error still reaches the async channel's handler at the end of the pipeline.
/// That handler ends the inbound sequence, so `run` throws and the agent exits.
///
/// The `IOError`s that SwiftNIO also survives, such as `EMFILE`, never get that far.
/// The async `bind` adds an `AcceptBackoffHandler` that backs off and does not forward them.
/// This handler therefore leaves them, and every other error, alone.
final class AcceptErrorFilter: ChannelInboundHandler, Sendable {
    typealias InboundIn = NIOAny

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        guard error is NIOFcntlFailedError else {
            context.fireErrorCaught(error)
            return
        }
        log.debug("dropped an accept error: \(String(describing: error), privacy: .public)")
    }
}

/// Serves the agent on a Unix socket.
public struct Server: Sendable {
    let agent: Agent
    let sync: SyncService?
    let backup: (any BackupCommands)?
    /// Called after a command reloaded the keys, as a key imported, created or deleted on this Mac.
    let onKeysChanged: (@Sendable () async -> Void)?
    let pool: NIOThreadPool
    /// The file this agent runs; nil refuses every private extension.
    /// A connection must run the same file to use a private extension.
    let executable: FileIdentity?

    public init(agent: Agent, sync: SyncService? = nil, backup: (any BackupCommands)? = nil, onKeysChanged: (@Sendable () async -> Void)? = nil) {
        self.init(agent: agent, sync: sync, backup: backup, onKeysChanged: onKeysChanged, executable: FileIdentity(executableOf: getpid()))
    }

    init(agent: Agent, sync: SyncService?, backup: (any BackupCommands)? = nil, onKeysChanged: (@Sendable () async -> Void)? = nil, executable: FileIdentity?) {
        self.agent = agent
        self.sync = sync
        self.backup = backup
        self.onKeysChanged = onKeysChanged
        pool = .singleton
        self.executable = executable
    }

    /// An accepted connection, with the process that opened it.
    private struct Accepted: Sendable {
        let channel: NIOAsyncChannel<ByteBuffer, ByteBuffer>
        let peerPID: pid_t
    }

    struct OtherUser: Error {}

    /// Listens on `path` until the task is cancelled.
    public func run(socketPath path: String) async throws {
        try await listen(socketPath: path, onListening: nil)
    }

    /// Fires an accept failure through `channel`'s pipeline, as SwiftNIO does when `fcntl` fails on an accepted socket.
    /// SwiftNIO gives `NIOFcntlFailedError` no public initializer.
    /// The error has no stored properties, and the empty tuple has the same layout.
    static func failAccept(on channel: any Channel) async throws {
        let error = unsafeBitCast((), to: NIOFcntlFailedError.self)
        try await channel.eventLoop.submit { channel.pipeline.fireErrorCaught(error) }.get()
    }

    /// Serves like `run`, and passes the server channel to `onListening` once the socket is bound.
    func listen(socketPath path: String, onListening: (@Sendable (any Channel) -> Void)?) async throws {
        await agent.reload()
        await sync?.start()
        let directory = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelInitializer { channel in
                channel.pipeline.addHandler(AcceptErrorFilter())
            }
            .bind(unixDomainSocketPath: path, cleanupExistingSocketFile: true) { channel in
                Self.accept(channel)
            }
        chmod(path, 0o600)
        log.notice("serving \(path, privacy: .public)")
        onListening?(server.channel)
        try await withThrowingDiscardingTaskGroup { group in
            group.addTask { try await sweep() }
            try await server.executeThenClose { inbound in
                for try await connection in inbound {
                    group.addTask { await serve(connection) }
                }
            }
        }
    }

    /// Accepts a connection only from a process of this user.
    private static func accept(_ channel: any Channel) -> EventLoopFuture<Accepted> {
        guard let provider = channel as? any SocketOptionProvider else {
            return channel.eventLoop.makeFailedFuture(OtherUser())
        }
        let credentials: EventLoopFuture<xucred> = provider.unsafeGetSocketOption(level: SOL_LOCAL, name: LOCAL_PEERCRED)
        let peer: EventLoopFuture<pid_t> = provider.unsafeGetSocketOption(level: SOL_LOCAL, name: LOCAL_PEERPID)
        return credentials.and(peer).flatMapThrowing { credentials, pid in
            guard credentials.cr_uid == getuid() else {
                log.error("refused a connection from uid \(credentials.cr_uid)")
                throw OtherUser()
            }
            try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(FrameDecoder()))
            return Accepted(channel: try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel), peerPID: pid)
        }
    }

    private func serve(_ accepted: Accepted) async {
        do {
            try await accepted.channel.executeThenClose { inbound, outbound in
                let state = Connection(peerPID: accepted.peerPID)
                for try await frame in inbound {
                    let body = await respond(to: Request(body: Data(buffer: frame)), on: state).body
                    var reply = ByteBuffer()
                    reply.writeInteger(UInt32(body.count))
                    reply.writeBytes(body)
                    try await outbound.write(reply)
                }
            }
        } catch {
            log.debug("connection closed: \(String(describing: error), privacy: .public)")
        }
    }

    func respond(to request: Request, on connection: Connection = Connection(peerPID: nil)) async -> Response {
        switch request {
        case .identities:
            return .identities(await agent.identities())
        case let .sign(blob, data, flags):
            guard let signer = await agent.signer(for: blob) else { return .failure }
            do {
                // Signing runs on the thread pool, so a slow Secure Enclave call blocks no event loop or actor.
                return .signature(try await pool.runIfActive { try signer.sign(data, flags: flags) })
            } catch {
                log.error("signing failed: \(String(describing: error), privacy: .public)")
                return .failure
            }
        case let .add(key, comment, constraints):
            return await agent.add(key, comment: comment, constraints: constraints)
        case let .remove(blob):
            return await agent.remove(blob: blob)
        case .removeAll:
            return await agent.removeAll()
        case let .extension(name, contents):
            return await respond(toExtension: name, contents: contents, on: connection)
        case .unsupported, .malformed:
            return .failure
        }
    }

    private func respond(toExtension name: String, contents: Data, on connection: Connection) async -> Response {
        if PrivateExtension.all.contains(name), connection.isForwarded || !isSigndCommand(connection) {
            return .failure
        }
        switch name {
        case Extension.query:
            return .query
        case Extension.sessionBind:
            await agent.recordSessionBind()
            if Self.isForwarding(contents) { connection.markForwarded() }
            return .success
        case PrivateExtension.reload:
            await agent.reload()
            await sync?.keysDidChange()
            await onKeysChanged?()
            return .success
        case PrivateExtension.sync:
            guard let sync else { return .failure }
            return Self.json(await sync.syncNow(), name: name)
        case PrivateExtension.syncState:
            guard let sync else { return .failure }
            return Self.json(await sync.snapshot(), name: name)
        case PrivateExtension.share:
            guard let sync, let key = Self.argument(contents) else { return .failure }
            return Self.json(await sync.share(key), name: name)
        case PrivateExtension.deleteShared:
            guard let sync, let key = Self.argument(contents) else { return .failure }
            return Self.json(await sync.deleteShared(key), name: name)
        case PrivateExtension.devices:
            guard let sync else { return .failure }
            return Self.json(await sync.devices(), name: name)
        case PrivateExtension.removeDevice:
            guard let sync, let id = Self.argument(contents) else { return .failure }
            return Self.json(await sync.removeDevice(id), name: name)
        case PrivateExtension.backupLogin:
            guard let backup, let argument = Self.argument(contents),
                  let request = try? JSONDecoder().decode(BackupLoginRequest.self, from: Data(argument.utf8))
            else { return .failure }
            return Self.json(await backup.logIn(token: request.token, vault: request.vault), name: name)
        case PrivateExtension.backupLogout:
            guard let backup else { return .failure }
            return Self.json(await backup.logOut(), name: name)
        case PrivateExtension.backupRestore:
            guard let backup, let argument = Self.argument(contents),
                  let request = try? JSONDecoder().decode(BackupRestoreRequest.self, from: Data(argument.utf8))
            else { return .failure }
            if request.listOnly { return Self.json(await backup.list(), name: name) }
            return Self.json(await backup.restore(names: request.names, all: request.all, local: request.local), name: name)
        case PrivateExtension.backupStatus:
            guard let backup else { return .failure }
            return Self.json(await backup.status(), name: name)
        case PrivateExtension.status:
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            guard let json = try? encoder.encode(await agent.status()) else { return .failure }
            var contents = Data()
            contents.appendString(json)
            return .extensionResponse(name: name, contents: contents)
        default:
            return .failure
        }
    }

    /// Whether the connection's process runs the same executable file as this agent, as `signd`'s own commands do.
    private func isSigndCommand(_ connection: Connection) -> Bool {
        guard let executable, let pid = connection.peerPID, let peer = FileIdentity(executableOf: pid) else { return false }
        return peer == executable
    }

    /// The one string argument of a private extension.
    private static func argument(_ contents: Data) -> String? {
        var reader = Reader(contents)
        guard let text = reader.readText(), reader.isAtEnd else { return nil }
        return text
    }

    private static func json(_ value: some Encodable, name: String) -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let json = try? encoder.encode(value) else { return .failure }
        var contents = Data()
        contents.appendString(json)
        return .extensionResponse(name: name, contents: contents)
    }

    /// Whether a `session-bind@openssh.com` message marks the connection as forwarded: its last field, after the host key,
    /// the session identifier and the signature.
    static func isForwarding(_ contents: Data) -> Bool {
        var reader = Reader(contents)
        guard reader.readString() != nil, reader.readString() != nil, reader.readString() != nil, let flag = reader.readByte() else { return false }
        return flag != 0
    }

    /// Drops expired keys at an interval set by the key lifetime: half of it, from 1 to 60 seconds.
    private func sweep() async throws {
        while true {
            let interval = min(60, max(1, await agent.lifetimeSeconds() / 2))
            try await Task.sleep(for: .seconds(interval))
            await agent.dropExpired(now: Date())
        }
    }
}

extension Agent {
    func lifetimeSeconds() -> TimeInterval { lifetime() }
}
