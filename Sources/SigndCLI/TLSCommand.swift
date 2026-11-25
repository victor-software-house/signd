import ArgumentParser
import Foundation
import KeychainIdentity
import SwiftASN1
import X509

/// `signd tls`: TLS client identities, each a Secure Enclave key with the certificate chain stored for it.
/// They live in their own keychain group, away from the SSH keys, and the agent never offers them.
struct TLSCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "tls",
        abstract: "Create, store and remove TLS client identities.",
        subcommands: [Create.self, Store.self, Remove.self]
    )

    /// The keychain access group of the identities, without the team identifier that comes in front of it.
    static let groupSuffix = "com.victor-software-house.identities"

    static func openStore() throws -> IdentityStore {
        do { return try IdentityStore(groupSuffix: groupSuffix) } catch { throw failure(error) }
    }

    /// The command's failure for an error of the identity library, in plain words.
    static func failure(_ error: some Error) -> Failure {
        guard let error = error as? KeychainIdentityError else { return Failure(error) }
        return Failure(message(for: error))
    }

    static func message(for error: KeychainIdentityError) -> String {
        switch error {
        case .notSigned:
            "this signd has no signing team, so it has no keychain group for TLS identities; run the installed Signd.app"
        case let .missingEntitlement(group):
            "this signd is not entitled to the keychain group \(group); its provisioning profile must list it"
        case let .notFound(name):
            "there is no TLS identity named \(name)"
        case let .alreadyExists(name):
            "a TLS identity named \(name) already exists"
        case .keyMismatch:
            "the first certificate of the chain is for another key than the identity's, so nothing was stored"
        case .lockedSinceBoot:
            "the keychain stays locked until this Mac is unlocked once after it starts; unlock it and run the command again"
        case let .keychain(status):
            "the keychain failed with status \(status)"
        }
    }

    /// The certificates of a PEM chain, in the order they are written: the leaf first.
    static func parseChain(_ data: Data) throws -> [Certificate] {
        let documents: [PEMDocument]
        do {
            documents = try PEMDocument.parseMultiple(pemString: String(decoding: data, as: UTF8.self))
        } catch {
            throw Failure("the input is not a PEM chain of certificates: \(error)")
        }
        guard !documents.isEmpty else { throw Failure("the input has no certificate; send the chain in PEM, leaf first") }
        return try documents.map { document in
            guard document.discriminator == "CERTIFICATE" else {
                throw Failure("the input has a \(document.discriminator) block, and only CERTIFICATE blocks belong in a chain")
            }
            do { return try Certificate(derEncoded: document.derBytes) } catch { throw Failure("a certificate of the chain cannot be read: \(error)") }
        }
    }

    struct Create: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Create the Secure Enclave key of a TLS identity.")
        @Argument(help: "The identity's name, unique among the TLS identities.") var name: String

        func run() throws {
            let store = try TLSCommand.openStore()
            do { _ = try store.create(name: name) } catch { throw TLSCommand.failure(error) }
        }
    }

    struct Store: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Store the certificate chain of a TLS identity, read in PEM from stdin.",
            discussion: "The chain starts with the leaf. A leaf for another key is refused, and the stored chain stays as it was."
        )
        @Argument(help: "The identity's name.") var name: String

        func run() throws {
            let chain = try TLSCommand.parseChain(FileHandle.standardInput.readDataToEndOfFile())
            let store = try TLSCommand.openStore()
            do {
                guard let identity = try store.identity(named: name) else { throw KeychainIdentityError.notFound(name: name) }
                try store.store(chain: chain, for: identity)
            } catch {
                throw TLSCommand.failure(error)
            }
        }
    }

    struct Remove: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Delete a TLS identity: its key, its leaf certificate and its chain.")
        @Argument(help: "The identity's name.") var name: String

        func run() throws {
            let store = try TLSCommand.openStore()
            do { try store.remove(name: name) } catch { throw TLSCommand.failure(error) }
        }
    }
}
