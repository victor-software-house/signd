import ArgumentParser
import CryptoKit
import Foundation
import KeychainIdentity
import SwiftASN1
import Testing
import X509
@testable import SigndCLI

/// A certificate for a software key, signed by another software key.
private func certificate(_ commonName: String, key: P256.Signing.PrivateKey, issuer: String, issuerKey: P256.Signing.PrivateKey) throws -> Certificate {
    let now = Date()
    return try Certificate(
        version: .v3,
        serialNumber: Certificate.SerialNumber(),
        publicKey: Certificate.PublicKey(key.publicKey),
        notValidBefore: now.addingTimeInterval(-3600),
        notValidAfter: now.addingTimeInterval(3600),
        issuer: DistinguishedName { CommonName(issuer) },
        subject: DistinguishedName { CommonName(commonName) },
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: Certificate.Extensions(),
        issuerPrivateKey: Certificate.PrivateKey(issuerKey)
    )
}

private func pem(_ certificates: [Certificate]) throws -> Data {
    Data(try certificates.map { try $0.serializeAsPEM().pemString + "\n" }.joined().utf8)
}

@Test func theTLSCommandsTakeTheIdentityName() throws {
    #expect(try TLSCommand.Create.parse(["mirror"]).name == "mirror")
    #expect(try TLSCommand.Store.parse(["mirror"]).name == "mirror")
    #expect(try TLSCommand.Remove.parse(["mirror"]).name == "mirror")
    #expect(throws: (any Error).self) { try TLSCommand.Create.parse([]) }
    #expect(throws: (any Error).self) { try TLSCommand.Store.parse([]) }
    #expect(throws: (any Error).self) { try TLSCommand.Remove.parse([]) }
}

@Test func theRootCommandRoutesTLSToItsSubcommands() throws {
    #expect((try Signd.parseAsRoot(["tls", "create", "mirror"]) as? TLSCommand.Create)?.name == "mirror")
    #expect((try Signd.parseAsRoot(["tls", "store", "mirror"]) as? TLSCommand.Store)?.name == "mirror")
    #expect((try Signd.parseAsRoot(["tls", "remove", "mirror"]) as? TLSCommand.Remove)?.name == "mirror")
}

@Test func aChainReadsLeafFirst() throws {
    let authorityKey = P256.Signing.PrivateKey()
    let leafKey = P256.Signing.PrivateKey()
    let authority = try certificate("authority", key: authorityKey, issuer: "authority", issuerKey: authorityKey)
    let leaf = try certificate("leaf", key: leafKey, issuer: "authority", issuerKey: authorityKey)
    let chain = try TLSCommand.parseChain(pem([leaf, authority]))
    #expect(chain == [leaf, authority])
}

@Test func inputThatIsNotACertificateChainIsRefused() throws {
    let request = Data("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n".utf8)
    let wrongBlock = #expect(throws: Failure.self) { try TLSCommand.parseChain(request) }
    #expect(wrongBlock?.description.contains("CERTIFICATE REQUEST") == true)
    let empty = #expect(throws: Failure.self) { try TLSCommand.parseChain(Data()) }
    #expect(empty?.description.contains("no certificate") == true)
    let text = #expect(throws: Failure.self) { try TLSCommand.parseChain(Data("hello".utf8)) }
    #expect(text?.description.contains("PEM") == true)
    // A block whose bytes are not a certificate.
    let garbage = Data("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".utf8)
    let bytes = #expect(throws: Failure.self) { try TLSCommand.parseChain(garbage) }
    #expect(bytes?.description.contains("cannot be read") == true)
}

@Test func eachIdentityErrorReadsInPlainWords() {
    #expect(TLSCommand.message(for: .notFound(name: "mirror")) == "there is no TLS identity named mirror")
    #expect(TLSCommand.message(for: .alreadyExists(name: "mirror")) == "a TLS identity named mirror already exists")
    #expect(TLSCommand.message(for: .missingEntitlement(group: "TEAM.group")).contains("TEAM.group"))
    #expect(TLSCommand.message(for: .keyMismatch).contains("another key"))
    #expect(TLSCommand.message(for: .keyMismatch).contains("nothing was stored"))
    #expect(TLSCommand.message(for: .keychain(-25300)) == "the keychain failed with status -25300")
    #expect(!TLSCommand.message(for: .notSigned).isEmpty)
    #expect(!TLSCommand.message(for: .lockedSinceBoot).isEmpty)
}

@Test func anErrorOfTheLibraryBecomesAFailureWithItsMessage() {
    #expect(TLSCommand.failure(KeychainIdentityError.keyMismatch).description == TLSCommand.message(for: .keyMismatch))
    #expect(TLSCommand.failure(Failure("other")).description == "other")
}
