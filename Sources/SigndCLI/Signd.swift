import AgentServer
import AppKit
import ArgumentParser
import Backup
import CloudKit
import Foundation
import KeyStore
import notify
import os
import ServiceManagement
import SSHEncoding
import Sync
import SystemConfiguration
import Updates

public struct Signd: ParsableCommand {
    public init() {}

    public static let configuration = CommandConfiguration(
        abstract: "An SSH agent for keys only its signed app can use, shared through iCloud.",
        version: signdVersion,
        subcommands: [KeyCommand.self, TLSCommand.self, DeviceCommand.self, BackupCommand.self, SyncNow.self, UpdateNow.self, Status.self, Config.self, Service.self, Serve.self, UpdaterDaemon.self, Postinstall.self]
    )
}

/// A failure the command reports and exits non-zero for.
struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
    init(_ error: some Error) { description = String(describing: error) }
}

struct JSONOption: ParsableArguments {
    @Flag(help: "Print one JSON document on stdout.")
    var json = false
    @OptionGroup var colorOption: ColorOption

    func print(_ value: some Encodable) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        Swift.print(String(decoding: try encoder.encode(value), as: UTF8.self))
    }
}

/// A key as commands print it.
struct KeySummary: Encodable {
    let name: String
    let type: String
    let algorithm: String
    let fingerprint: String
    let comment: String
    let hosts: [String]
    let source: String
    let publicKey: String
    let created: Date

    init(_ key: StoredKey) {
        let publicKey = key.publicKey
        name = key.name
        type = key.kind.rawValue
        algorithm = publicKey?.keyType ?? "?"
        fingerprint = publicKey?.fingerprint ?? "?"
        comment = key.comment
        hosts = key.hosts
        source = key.source
        self.publicKey = publicKey?.openSSHLine(comment: key.displayComment) ?? ""
        created = key.created
    }
}

func storedKeys() throws -> [StoredKey] {
    do { return try KeychainStore().list() } catch { throw Failure(error) }
}

func storedKey(_ name: String) throws -> StoredKey {
    guard let key = try storedKeys().first(where: { $0.name == name }) else { throw Failure(StoreError.notFound(name)) }
    return key
}

struct KeyCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "key", abstract: "Create, list, show and delete keys.", subcommands: [Create.self, Import.self, Share.self, List.self, Show.self, Delete.self])

    /// The kinds of key `key create` makes.
    enum KeyType: String, ExpressibleByArgument, CaseIterable {
        case secureEnclave = "secure-enclave"
        case ed25519
        case rsa3072 = "rsa-3072"
        case rsa4096 = "rsa-4096"

        var generated: GeneratedKeyType? {
            switch self {
            case .secureEnclave: nil
            case .ed25519: .ed25519
            case .rsa3072: .rsa3072
            case .rsa4096: .rsa4096
            }
        }
    }

    /// Checks a new key's name and host patterns, and that the name is free.
    static func checkNew(name: String, hosts: [String], store: KeychainStore) throws {
        guard StoredKey.isValidName(name) else { throw Failure(StoreError.invalidName(name)) }
        if let host = hosts.first(where: { !StoredKey.isValidHost($0) }) { throw Failure(StoreError.invalidHost(host)) }
        do {
            if try store.list().contains(where: { $0.name == name }) { throw StoreError.duplicate(name) }
        } catch {
            throw Failure(error)
        }
    }

    /// Stores a new key, tells a running agent, shares it unless `local`, and prints the public key.
    static func finish(_ key: StoredKey, store: KeychainStore, local: Bool, output: JSONOption) throws {
        do { try store.add(key) } catch { throw Failure(error) }
        let client = AgentClient(path: defaultSocketPath)
        client.reload()
        var printed = key
        var failure: Failure?
        if !local && key.kind == .wrapped {
            switch client.share(key.name) {
            case nil:
                failure = Failure("created \(key.name) on this Mac only, since signd cannot reach the agent; to share it, run signd key share \(key.name)")
            case let result? where result.outcome == .failed:
                failure = Failure("created \(key.name) on this Mac only: \(result.message ?? "the share failed for an unknown reason"); to share it, run signd key share \(key.name)")
            case let result? where result.outcome == .off:
                note(result.message ?? "sync is off; \(key.name) stays on this Mac")
            case _:
                printed = (try? storedKey(key.name)) ?? key
            }
        }
        if output.json { try output.print(KeySummary(printed)) } else { print(KeySummary(printed).publicKey) }
        if let failure { throw failure }
    }

    /// Writes a note to stderr, so stdout keeps only the command's output.
    static func note(_ text: String) {
        let style = TerminalStyle(.standardError, choice: .current)
        let line = style.isColored ? style.warning(text) : "▲ \(text)"
        FileHandle.standardError.write(Data("\(line)\n".utf8))
    }

    struct Create: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Create a key and print its public key.")
        @Argument(help: "The key's name: letters, digits, '-', '_' and '.'.") var name: String
        @Option(help: "The key type: a Secure Enclave P-256 key, or an Ed25519 or RSA key wrapped by the Secure Enclave.") var type = KeyType.secureEnclave
        @Option(help: "The comment ssh-add shows; the name when empty.") var comment = ""
        @Option(name: .customLong("host"), help: "An SSH host pattern that uses this key; repeat for more.") var hosts: [String] = []
        @Flag(help: "Keep the key on this Mac instead of sharing it through iCloud. A Secure Enclave key always stays.") var local = false
        @OptionGroup var output: JSONOption

        func run() throws {
            let store = KeychainStore()
            try checkNew(name: name, hosts: hosts, store: store)
            do {
                let key: StoredKey
                if let generated = type.generated {
                    let privateKey = try KeyImport.generate(generated)
                    key = try KeychainStore.makeWrappedKey(name: name, privateKey: privateKey, comment: comment, hosts: hosts, source: "local")
                } else {
                    key = try KeychainStore.makeSecureEnclaveKey(name: name, comment: comment, hosts: hosts)
                }
                try finish(key, store: store, local: local, output: output)
            } catch let error as Failure {
                throw error
            } catch {
                throw Failure(error)
            }
        }
    }

    struct Import: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Import a private key file, or stdin with '-', wrapped by the Secure Enclave, and print its public key.",
            discussion: "A passphrase-protected file must be given as a file: ssh-add asks for its passphrase."
        )
        @Argument(help: "The key's name: letters, digits, '-', '_' and '.'.") var name: String
        @Argument(help: "An OpenSSH, PKCS#1, PKCS#8 or SEC1 private key file, or '-' for stdin.") var file: String
        @Option(help: "The comment ssh-add shows; the key's own comment, or the name, when empty.") var comment: String?
        @Option(name: .customLong("host"), help: "An SSH host pattern that uses this key; repeat for more.") var hosts: [String] = []
        @Flag(help: "Keep the key on this Mac instead of sharing it through iCloud.") var local = false
        @OptionGroup var output: JSONOption

        func run() throws {
            let store = KeychainStore()
            try checkNew(name: name, hosts: hosts, store: store)
            let fromStdin = file == "-"
            guard let data = fromStdin ? FileHandle.standardInput.readDataToEndOfFile() : FileManager.default.contents(atPath: file) else {
                throw Failure("cannot read \(file)")
            }
            do {
                let imported: (PrivateKey, String)
                switch try KeyImport.parse(data) {
                case let .key(key, own):
                    imported = (key, own)
                case .encrypted:
                    if fromStdin { throw ImportError.encryptedKeyOnStdin }
                    imported = try KeyImport.importWithSSHAdd(file: file)
                }
                let key = try KeychainStore.makeWrappedKey(name: name, privateKey: imported.0, comment: comment ?? imported.1, hosts: hosts, source: "import")
                try finish(key, store: store, local: local, output: output)
            } catch let error as Failure {
                throw error
            } catch {
                throw Failure(error)
            }
        }
    }

    struct Share: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Share a key of this Mac with every device on the iCloud account.")
        @Argument var name: String
        @OptionGroup var colorOption: ColorOption

        func run() throws {
            guard let result = AgentClient(path: defaultSocketPath).share(name) else { throw Failure("cannot reach the agent") }
            switch result.outcome {
            case .done: print(colorOption.standardOutput.success("shared \(name)"))
            case .off: throw Failure(result.message ?? "sync is off")
            case .failed: throw Failure(result.message ?? "the share failed")
            }
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List the stored keys.")
        @OptionGroup var output: JSONOption

        func run() throws {
            let keys = try storedKeys().map(KeySummary.init)
            if output.json { return try output.print(keys) }
            for key in keys {
                let hosts = key.hosts.isEmpty ? "-" : key.hosts.joined(separator: ",")
                print([key.name, key.type, key.algorithm, key.fingerprint, key.source, "hosts=\(hosts)", key.comment].joined(separator: "  "))
            }
        }
    }

    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print one key's OpenSSH public key.")
        @Argument var name: String
        @OptionGroup var output: JSONOption

        func run() throws {
            let key = KeySummary(try storedKey(name))
            if output.json { try output.print(key) } else { print(key.publicKey) }
        }
    }

    struct Delete: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Delete one key; a shared key is deleted on every device.")
        @Argument var name: String

        func run() throws {
            let key = try storedKey(name)
            let client = AgentClient(path: defaultSocketPath)
            if key.isShared {
                guard let result = client.deleteShared(name) else { throw Failure("cannot reach the agent, which deletes a shared key on every Mac") }
                guard result.outcome == .done else { throw Failure(result.message ?? "the delete failed") }
                return
            }
            do { try KeychainStore().delete(name: name) } catch { throw Failure(error) }
            client.reload()
        }
    }
}

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Show the agent, its keys and the iCloud sync; exits non-zero when the agent is not running.")
    @Option(help: "The agent socket.") var socket = defaultSocketPath
    @OptionGroup var output: JSONOption

    struct Report: Encodable {
        let version: String
        let socket: String
        let agentAnswers: Bool
        let agent: AgentStatus?
        let sync: SyncStatus
        let backup: BackupStatus?
        let update: UpdateStatus
        let loginItem: LoginItemState
        let isSSHIncludeEnabled: Bool

        enum CodingKeys: String, CodingKey {
            case version, socket, agentAnswers, agent, sync, backup, update, loginItem
            case isSSHIncludeEnabled = "sshInclude"
        }
    }

    /// The state of the iCloud line, by the result of the last check; a state with no level stays plain.
    static func level(of result: CheckOutcome?) -> TerminalStyle.Level? {
        switch result {
        case .ok?: .inOrder
        case .off?: .waiting
        case .accountUnavailable?, .failed?, .throttled?: .failed
        case .stopped?, nil: nil
        }
    }

    func run() throws {
        let client = AgentClient(path: socket)
        let agent = client.status()
        let sync = SyncStatus(state: client.syncState() ?? SyncState.load())
        let backup = BackupCommand.status(client: client, settings: Settings())
        let update = UpdateStatus()
        let loginItem = Service.loginItem
        let isSSHIncludeEnabled = SSHInclude.isEnabled(home: FileManager.default.homeDirectoryForCurrentUser)
        let report = Report(version: signdVersion, socket: socket, agentAnswers: agent != nil, agent: agent, sync: sync, backup: backup, update: update, loginItem: loginItem, isSSHIncludeEnabled: isSSHIncludeEnabled)
        if output.json {
            try output.print(report)
        } else {
            let out = output.colorOption.standardOutput
            print("signd \(signdVersion)")
            print("socket  \(socket)")
            if let agent {
                print("agent   \(out.value("running (pid \(agent.pid), \(agent.version))", .inOrder))")
                if let error = agent.storeError { print("store   \(error)") }
                for key in agent.keys { print("key     \(key.name)  \(key.isInMemory ? "in memory" : "not in memory")") }
                if agent.memoryOnlyKeys > 0 { print("memory-only keys  \(agent.memoryOnlyKeys)") }
            } else {
                print("agent   \(out.value("not running", .failed))")
            }
            let loginItemText = "\(loginItem.text)\(loginItem == .enabled ? "" : "; run signd service enable")"
            print("login item  \(out.value(loginItemText, loginItem == .enabled ? .inOrder : .waiting))")
            let sshConfigText = isSSHIncludeEnabled ? "includes ~/.ssh/signd/config" : "has no Include line for ~/.ssh/signd/config; run signd service enable"
            print("ssh config  \(out.value(sshConfigText, isSSHIncludeEnabled ? .inOrder : .waiting))")
            print("icloud  \(out.value(sync.state, Self.level(of: sync.lastResult)))\(sync.lastMessage.map { ": \($0)" } ?? "")")
            print("interval  \(sync.interval.value) (\(sync.interval.source.rawValue))")
            if let at = sync.lastCheck, let result = sync.lastResult {
                let level: TerminalStyle.Level? = switch result {
                case .ok: .inOrder
                case .failed: .failed
                case .throttled, .accountUnavailable, .stopped, .off: nil
                }
                print("last check  \(at.formatted(.iso8601)) \(out.value(result.rawValue, level)), \(sync.requests) requests")
            }
            if let next = sync.nextAttempt { print("next check  \(next.formatted(.iso8601))") }
            if let push = sync.lastPush { print("last push  \(push.formatted(.iso8601))") }
            print("devices  \(sync.devices)")
            for setting in sync.ignoredSettings { print("ignored  \(setting.key) \(setting.value) (local): \(setting.reason)") }
            for key in sync.skipped { print("\(out.value(key.kind == .waiting ? "waiting" : "skipped", .waiting))  \(key.name): \(key.reason)") }
            for line in backup.lines { print(line) }
            for line in update.lines { print(line) }
        }
        if agent == nil { throw ExitCode.failure }
    }
}

struct DeviceCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "device", abstract: "List and remove the devices that share keys through iCloud.", subcommands: [List.self, Remove.self])

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List the devices on the iCloud account.")
        @OptionGroup var output: JSONOption

        func run() throws {
            guard let devices = AgentClient(path: defaultSocketPath).devices() else { throw Failure("cannot reach the agent") }
            if output.json { return try output.print(devices) }
            for device in devices { print([device.name, device.id, device.isThisDevice ? "this device" : ""].joined(separator: "  ")) }
        }
    }

    struct Remove: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Remove a device that no longer runs signd, and drop its copies of every shared key.",
            discussion: "A removal that fails partway, or that runs while another Mac checks iCloud, may leave a copy. Run it again to drop it."
        )
        @Argument(help: "The device's id, as signd device list prints it.") var id: String
        @OptionGroup var colorOption: ColorOption

        func run() throws {
            guard let result = AgentClient(path: defaultSocketPath).removeDevice(id) else { throw Failure("cannot reach the agent") }
            guard result.outcome == .done else { throw Failure(result.message ?? "the removal failed") }
            print(colorOption.standardOutput.success("removed \(id)"))
        }
    }
}

struct SyncNow: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "sync", abstract: "Check iCloud now, wait for the result, and report what changed.")
    @Option(help: "The agent socket.") var socket = defaultSocketPath
    @OptionGroup var output: JSONOption

    func run() throws {
        guard let summary = AgentClient(path: socket).sync() else { throw Failure("cannot reach the agent") }
        if output.json {
            try output.print(summary)
        } else {
            print("\(summary.outcome.rawValue): \(summary.requests) requests")
            if let message = summary.message { print(message) }
            for name in summary.added { print("added  \(name)") }
            for name in summary.replaced { print("replaced  \(name)") }
            for name in summary.removed { print("removed  \(name)") }
            for name in summary.sealed { print("shared with a new device  \(name)") }
            if summary.skipped > 0 { print("skipped  \(summary.skipped); see signd status") }
        }
        if summary.outcome != .ok { throw ExitCode.failure }
    }
}

struct Config: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Read and change settings.", subcommands: [Get.self, Set.self, Unset.self])

    struct SettingName: ExpressibleByArgument {
        let key: Settings.Key
        init?(argument: String) {
            guard let key = Settings.Key(rawValue: argument) else { return nil }
            self.key = key
        }

        static var allValueStrings: [String] { Settings.Key.allCases.map(\.rawValue) }
    }

    struct Get: ParsableCommand {
        @Argument var name: SettingName
        func run() {
            print(Settings().resolve(name.key).value)
        }
    }

    struct Set: ParsableCommand {
        @Argument var name: SettingName
        @Argument var value: String
        func run() throws {
            do { try Settings().set(name.key, to: value) } catch { throw Failure(error) }
        }
    }

    struct Unset: ParsableCommand {
        @Argument var name: SettingName
        func run() {
            Settings().unset(name.key)
        }
    }
}

struct Service: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run the agent at login, or stop doing so.",
        subcommands: [Enable.self, Disable.self, Status.self, Restart.self, Log.self]
    )
    static var agent: SMAppService { .agent(plistName: "com.victor-software-house.signd.plist") }
    static var loginItem: LoginItemState { LoginItemState(agent.status) }

    /// Whether an agent answers within `seconds`, one other than process `old` when it is given.
    /// That covers an agent that launchd is starting.
    static func agentAnswers(within seconds: Double = 2, replacing old: Int32? = nil) -> Bool {
        let deadline = Date.now.addingTimeInterval(seconds)
        repeat {
            if let status = AgentClient(path: defaultSocketPath).status(), status.pid != old { return true }
            usleep(100_000)
        } while Date.now < deadline
        return false
    }

    /// Restarts the agent's job and waits up to 5 seconds for a new process to answer.
    static func restart() throws {
        let old = AgentClient(path: defaultSocketPath).status()?.pid
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["kickstart", "-k", "gui/\(getuid())/com.victor-software-house.signd"]
        do { try process.run() } catch { throw Failure("cannot run launchctl: \(error)") }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Failure("launchctl kickstart failed with status \(process.terminationStatus)") }
        guard agentAnswers(within: 5, replacing: old) else {
            // kickstart replaces only launchd's job, so a process started by hand keeps the socket.
            if let old, AgentClient(path: defaultSocketPath).status()?.pid == old {
                throw Failure("process \(old) still serves the socket, and launchd did not start it; stop that process and try again")
            }
            throw Failure("the agent did not start again after the restart")
        }
    }

    struct Enable: ParsableCommand {
        @Flag(help: "Run from the login hook: change nothing when the login item is enabled, never open System Settings, and exit 0 while approval is pending.") var atLogin = false
        @OptionGroup var colorOption: ColorOption

        func run() throws {
            let out = colorOption.standardOutput
            // At login, launchd starts an enabled agent itself, and it may not answer yet.
            if atLogin, Service.agent.status == .enabled { return }
            // A config that cannot be written fails the command after the login item is in order, so the agent still starts.
            var includeFailed = false
            do {
                if try SSHInclude.enable(home: FileManager.default.homeDirectoryForCurrentUser) { print(out.success("added \(SSHInclude.line) to ~/.ssh/config")) }
            } catch {
                KeyCommand.note("cannot add the Include line to ~/.ssh/config: \(error)")
                includeFailed = true
            }
            switch Service.agent.status {
            case .enabled where Service.agentAnswers():
                // An agent started before an install over it keeps serving the old version until it restarts.
                if let running = AgentClient(path: defaultSocketPath).status()?.version, running != signdVersion {
                    try Service.restart()
                    let now = AgentClient(path: defaultSocketPath).status()?.version
                    guard now == signdVersion else {
                        throw Failure("the agent restarted on \(now ?? "an unknown version"), not on \(signdVersion)")
                    }
                    print(out.success("enabled signd and moved the agent from \(running) to \(signdVersion)"))
                } else {
                    print(out.success("enabled"))
                }
            case .enabled:
                // The cask's uninstall step removes the job from launchd while the login item stays enabled.
                // An upgrade also runs that step, and registering again restores the job.
                do {
                    try Service.agent.unregister()
                    try Service.agent.register()
                } catch {
                    throw Failure("cannot register the agent again: \(error)")
                }
                print(out.success("enabled"))
            case .requiresApproval:
                if atLogin { return }
                SMAppService.openSystemSettingsLoginItems()
                throw Failure("approve signd in System Settings, General, Login Items")
            default:
                var registerError: (any Error)?
                do { try Service.agent.register() } catch { registerError = error }
                if Service.agent.status == .requiresApproval {
                    if atLogin { return }
                    SMAppService.openSystemSettingsLoginItems()
                    throw Failure("approve signd in System Settings, General, Login Items")
                }
                if let registerError { throw Failure("cannot register the agent: \(registerError)") }
                print(out.success(Service.agent.status == .enabled ? "enabled" : "registered"))
            }
            if includeFailed { throw ExitCode.failure }
        }
    }

    struct Disable: ParsableCommand {
        @OptionGroup var colorOption: ColorOption

        func run() throws {
            let out = colorOption.standardOutput
            guard Service.agent.status != .notRegistered else { return print(out.warning("not registered")) }
            do { try Service.agent.unregister() } catch { throw Failure("cannot unregister the agent: \(error)") }
            print(out.success("disabled"))
        }
    }

    struct Status: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the login item and whether the agent answers.")
        @OptionGroup var colorOption: ColorOption

        func run() {
            let out = colorOption.standardOutput
            let loginItem = Service.loginItem
            print("login item  \(out.value(loginItem.text, loginItem == .enabled ? .inOrder : .waiting))")
            if let agent = AgentClient(path: defaultSocketPath).status() {
                print("agent  \(out.value("running (\(agent.version))", .inOrder))")
            } else {
                print("agent  \(out.value("not running", .failed))")
            }
        }
    }

    struct Restart: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Restart the agent and wait until it runs again; exits non-zero when it is not back within 5 seconds.")
        @OptionGroup var colorOption: ColorOption

        func run() throws {
            try Service.restart()
            print(colorOption.standardOutput.success("restarted"))
        }
    }

    struct Log: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the agent's log of the last hour, or follow it.")
        @Flag(help: "Stream new entries until interrupted, instead of showing the last hour.") var follow = false

        /// The arguments of `/usr/bin/log` for the agent's subsystem.
        static func arguments(follow: Bool) -> [String] {
            (follow ? ["stream", "--level", "debug"] : ["show", "--last", "1h", "--info", "--debug"]) + ["--predicate", "subsystem == \"com.victor-software-house.signd\""]
        }

        func run() throws {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
            process.arguments = Self.arguments(follow: follow)
            do { try process.run() } catch { throw Failure("cannot run log: \(error)") }
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw ExitCode(process.terminationStatus) }
        }
    }
}

/// The login item's state, as `signd status` prints it and reports it in JSON.
enum LoginItemState: String, Encodable {
    case enabled
    case requiresApproval
    case notRegistered
    case notFound
    case unknown

    init(_ status: SMAppService.Status) {
        switch status {
        case .enabled: self = .enabled
        case .requiresApproval: self = .requiresApproval
        case .notRegistered: self = .notRegistered
        case .notFound: self = .notFound
        @unknown default: self = .unknown
        }
    }

    var text: String {
        switch self {
        case .enabled: "enabled"
        case .requiresApproval: "requires approval"
        case .notRegistered: "not registered"
        case .notFound: "not found"
        case .unknown: "unknown"
        }
    }
}

struct Serve: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Run the agent in the foreground.")
    @Option(help: "The socket to listen on.") var socket = defaultSocketPath

    func run() throws {
        signal(SIGPIPE, SIG_IGN)
        let settings = Settings()
        let store = KeychainStore()
        let socketPath = socket
        let log = Logger(subsystem: "com.victor-software-house.signd", category: "agent")
        let agent = Agent(
            store: store, version: signdVersion, lifetime: { settings.resolve(.keyLifetime).seconds },
            onKeysRead: { keys in
                do {
                    try Routing.write(keys, socket: socketPath, home: FileManager.default.homeDirectoryForCurrentUser)
                } catch {
                    log.error("cannot write the SSH routing files: \(String(describing: error), privacy: .public)")
                }
            }
        )
        // A build without an iCloud container in its signature never touches CloudKit, which would stop the process.
        let cloud: (any CloudStore)? = CloudContainer.signed.map { CloudKitStore(containerID: $0) }
        let tokens = BackupTokenStore()
        let readDevice: @Sendable () throws(StoreError) -> DeviceKey = { () throws(StoreError) -> DeviceKey in try DeviceKeyStore().readOrCreate() }
        let openKey: KeyOpener = { key throws(SignError) in try Wrapping.openStored(key) }
        // The backup needs the lease in iCloud, so a build without the entitlement has none.
        // A run does nothing while no backup token is stored.
        let backup: BackupService? = cloud.map { cloud in
            let run = BackupRun(
                BackupRun.Dependencies(
                    cloud: cloud, store: store, tokens: tokens, device: readDevice, open: openKey, openVault: OnePasswordVault.opener(version: signdVersion),
                    removal: { BackupRemoval(rawValue: settings.text(.backupRemoved)) ?? .delete }
                )
            )
            return BackupService(BackupService.Dependencies(run: { await run.perform() }, schedule: { BackupSchedule(settings: settings) }))
        }
        let restore = BackupRestore(
            BackupRestore.Dependencies(
                tokens: tokens, openVault: OnePasswordVault.opener(version: signdVersion), vault: { settings.text(.backupVault) }, store: store,
                wrap: { (name, key, comment, hosts) throws(StoreError) -> StoredKey in
                    try KeychainStore.makeWrappedKey(name: name, privateKey: key, comment: comment, hosts: hosts, source: "backup")
                }
            )
        )
        let sync = SyncService(
            SyncService.Dependencies(
                cloud: cloud, store: store, device: readDevice, open: openKey,
                tokens: tokens, openSecret: { sealed, device in try Wrapping.openSecret(sealed, handle: device.handle) }, version: signdVersion,
                interval: { settings.resolve(.interval).seconds }, onSharedKeysChanged: {
                    await agent.reload()
                    await backup?.keysDidChange()
                }
            )
        )
        let server = Server(
            agent: agent, sync: sync,
            backup: BackupAgent(
                service: BackupLoginService(sync: sync, version: signdVersion), restorer: restore, sync: sync, agent: agent, backup: backup, tokens: tokens,
                settings: settings
            ),
            onKeysChanged: { await backup?.keysDidChange() }
        )
        // A setting that `signd config set` writes in another process reaches the waiting backup through this notification.
        // The registration lasts as long as the process, which never leaves this function.
        var settingsToken: Int32 = 0
        if backup != nil {
            let status = notify_register_dispatch(Settings.changedNotification, &settingsToken, DispatchQueue.global(qos: .utility)) { _ in
                Task { await backup?.scheduleDidChange() }
            }
            if status != 0 { log.error("cannot watch for changed settings: notify status \(status)") }
        }
        Task.detached {
            await backup?.start()
            do {
                try await server.run(socketPath: socketPath)
            } catch {
                log.fault("the agent stopped: \(String(describing: error), privacy: .public)")
                Darwin.exit(1)
            }
        }
        guard cloud != nil else { dispatchMain() }
        // Pushes reach only a running application, so the agent runs one, with no window and no Dock icon.
        MainActor.assumeIsolated {
            let app = NSApplication.shared
            app.setActivationPolicy(.accessory)
            let receiver = PushReceiver(sync: sync)
            app.delegate = receiver
            NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: nil) { _ in sync.accountChanged() }
            withExtendedLifetime(receiver) { app.run() }
        }
    }
}

/// The package's postinstall step runs as root.
/// It links `/usr/local/bin/signd` to the app and loads the updater daemon, then starts the agent again as the user at the console.
///
/// A cask upgrade first removes the agent's job from launchd, so `service enable` registers the login item again.
/// With nobody logged in, the login item starts the agent at the next login. It never fails the install.
struct Postinstall: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Link the command and start the agent as the console user after the package installs.", shouldDisplay: false)
    @Option(help: .hidden) var root = "/"
    @Flag(help: .hidden) var linkOnly = false

    func run() throws {
        let log = Logger(subsystem: "com.victor-software-house.signd", category: "install")
        do {
            if try CommandLink.install(root: URL(fileURLWithPath: root, isDirectory: true)) == .kept {
                log.notice("/usr/local/bin/signd is not a symbolic link, so it stays as it is")
            }
        } catch {
            if linkOnly { throw Failure(error) }
            log.error("cannot link /usr/local/bin/signd: \(String(describing: error), privacy: .public)")
        }
        if linkOnly { return }
        if root == "/" {
            // The daemon is system-wide, so it loads with nobody logged in.
            // A first install has nothing to boot out, and a bootout can return before launchd has removed the job, so the bootstrap retries.
            func launchctl(_ arguments: [String]) -> Int32? {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
                process.arguments = arguments
                do {
                    try process.run()
                    process.waitUntilExit()
                    return process.terminationStatus
                } catch {
                    log.error("cannot run launchctl \(arguments[0], privacy: .public): \(String(describing: error), privacy: .public)")
                    return nil
                }
            }
            _ = launchctl(["bootout", "system/com.victor-software-house.signd.updater"])
            var status: Int32?
            for attempt in 1...10 {
                status = launchctl(["bootstrap", "system", "/Library/LaunchDaemons/com.victor-software-house.signd.updater.plist"])
                if status == 0 || status == nil { break }
                if attempt < 10 { Thread.sleep(forTimeInterval: 0.5) }
            }
            if let status, status != 0 {
                log.error("launchctl bootstrap of the updater failed with status \(status)")
            }
        }
        var uid: uid_t = 0
        guard let user = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?, uid != 0, user != "loginwindow" else { return }
        let signd = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["asuser", String(uid), "/usr/bin/sudo", "-u", user, signd, "service", "enable"]
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            log.error("cannot start the agent for \(user, privacy: .public): \(String(describing: error), privacy: .public)")
        }
    }
}

/// The symbolic link `/usr/local/bin/signd`, where every shell finds the command.
enum CommandLink {
    enum Outcome { case linked, kept }

    static let target = "/Applications/Signd.app/Contents/MacOS/signd"

    /// Makes `usr/local/bin/signd` under `root` a symbolic link to the app's executable.
    /// A missing `usr/local/bin` is created with mode 755, and owned by root:wheel when this runs as root.
    /// A symbolic link there is replaced, whatever it points to, and a link to a folder is not followed.
    /// Anything else there is not signd's, so it stays.
    static func install(root: URL) throws -> Outcome {
        let manager = FileManager.default
        let folder = root.appendingPathComponent("usr/local/bin", isDirectory: true)
        if !manager.fileExists(atPath: folder.path) {
            var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o755]
            if geteuid() == 0 {
                attributes[.ownerAccountID] = 0
                attributes[.groupOwnerAccountID] = 0
            }
            try manager.createDirectory(at: folder, withIntermediateDirectories: true, attributes: attributes)
            try manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
        }
        let link = folder.appendingPathComponent("signd")
        var info = stat()
        if lstat(link.path, &info) == 0 {
            guard info.st_mode & S_IFMT == S_IFLNK else { return .kept }
            if try manager.destinationOfSymbolicLink(atPath: link.path) == target { return .linked }
            try manager.removeItem(at: link)
        }
        try manager.createSymbolicLink(atPath: link.path, withDestinationPath: target)
        return .linked
    }
}
