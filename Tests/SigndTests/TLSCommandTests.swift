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
    let request = try TLSCommand.CSR.parse(["mirror", "--common-name", "alpha", "--organization", "Example"])
    #expect(request.name == "mirror")
    #expect(request.commonName == "alpha")
    #expect(request.organization == "Example")
    #expect(try TLSCommand.CSR.parse(["mirror", "--common-name", "alpha"]).organization == nil)
    #expect(try TLSCommand.Remove.parse(["mirror"]).name == "mirror")
    #expect(throws: (any Error).self) { try TLSCommand.Create.parse([]) }
    #expect(throws: (any Error).self) { try TLSCommand.Store.parse([]) }
    #expect(throws: (any Error).self) { try TLSCommand.CSR.parse(["mirror"]) }
    #expect(throws: (any Error).self) { try TLSCommand.CSR.parse(["--common-name", "alpha"]) }
    #expect(throws: (any Error).self) { try TLSCommand.Remove.parse([]) }
}

@Test func theRootCommandRoutesTLSToItsSubcommands() throws {
    #expect((try Signd.parseAsRoot(["tls", "create", "mirror"]) as? TLSCommand.Create)?.name == "mirror")
    #expect((try Signd.parseAsRoot(["tls", "csr", "mirror", "--common-name", "alpha"]) as? TLSCommand.CSR)?.commonName == "alpha")
    #expect((try Signd.parseAsRoot(["tls", "store", "mirror"]) as? TLSCommand.Store)?.name == "mirror")
    #expect((try Signd.parseAsRoot(["tls", "remove", "mirror"]) as? TLSCommand.Remove)?.name == "mirror")
    #expect(try Signd.parseAsRoot(["tls", "list"]) is TLSCommand.List)
}

@Test func theListTakesTheJSONFlag() throws {
    #expect(try TLSCommand.List.parse([]).output.json == false)
    #expect(try TLSCommand.List.parse(["--json"]).output.json == true)
    #expect((try Signd.parseAsRoot(["tls", "list", "--json"]) as? TLSCommand.List)?.output.json == true)
    #expect(throws: (any Error).self) { try TLSCommand.List.parse(["mirror"]) }
}

/// The two-certificate chain of the listing tests: a leaf and its authority.
private func listedChain() throws -> [Certificate] {
    let authorityKey = P256.Signing.PrivateKey()
    let authority = try certificate("authority", key: authorityKey, issuer: "authority", issuerKey: authorityKey)
    let leaf = try certificate("leaf", key: P256.Signing.PrivateKey(), issuer: "authority", issuerKey: authorityKey)
    return [leaf, authority]
}

private func json(_ rows: [TLSCommand.IdentityRow]) throws -> [[String: Any]] {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(rows)
    return try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
}

@Test func theRowOfAnIdentityWithAChainShowsItsLeaf() throws {
    let chain = try listedChain()
    let row = TLSCommand.row(name: "mirror", chain: chain)
    #expect(row.name == "mirror")
    #expect(row.subject == "CN=leaf")
    #expect(row.issuer == "CN=authority")
    #expect(row.expiry == chain[0].notValidAfter)
    #expect(row.chainLength == 2)
}

@Test func theRowOfAnIdentityWithoutAChainHasNoSubjectIssuerOrExpiry() {
    let row = TLSCommand.row(name: "mirror", chain: [])
    #expect(row == TLSCommand.IdentityRow(name: "mirror", subject: nil, issuer: nil, expiry: nil, chainLength: 0))
}

@Test func theTextLineSeparatesTheFieldsByTwoSpaces() throws {
    let chain = try listedChain()
    let line = TLSCommand.row(name: "mirror", chain: chain).text
    #expect(line == "mirror  CN=leaf  CN=authority  expires \(chain[0].notValidAfter.formatted(.iso8601))  chain=2")
    #expect(TLSCommand.row(name: "mirror", chain: []).text == "mirror  waiting for a certificate")
}

@Test func theJSONListingHasTheFieldsAndTheExpiryInISO8601() throws {
    let chain = try listedChain()
    let rows = try json([TLSCommand.row(name: "mirror", chain: chain)])
    #expect(rows.count == 1)
    #expect(rows[0]["name"] as? String == "mirror")
    #expect(rows[0]["subject"] as? String == "CN=leaf")
    #expect(rows[0]["issuer"] as? String == "CN=authority")
    #expect(rows[0]["expiry"] as? String == chain[0].notValidAfter.formatted(.iso8601))
    #expect(rows[0]["chainLength"] as? Int == 2)
}

@Test func theJSONListingOfAnIdentityWithoutAChainHasNoSubjectIssuerOrExpiry() throws {
    let rows = try json([TLSCommand.row(name: "mirror", chain: [])])
    #expect(rows.count == 1)
    #expect(rows[0]["name"] as? String == "mirror")
    #expect(rows[0]["subject"] == nil)
    #expect(rows[0]["issuer"] == nil)
    #expect(rows[0]["expiry"] == nil)
    #expect(rows[0]["chainLength"] as? Int == 0)
}

@Test func theSubjectHasTheCommonNameAndTheOrganizationWhenGiven() throws {
    #expect(String(describing: try TLSCommand.subject(commonName: "alpha", organization: "Example")) == "CN=alpha,O=Example")
    #expect(String(describing: try TLSCommand.subject(commonName: "alpha", organization: nil)) == "CN=alpha")
}

@Test func anEmptyCommonNameOrOrganizationIsRefused() {
    let commonName = #expect(throws: Failure.self) { try TLSCommand.subject(commonName: "", organization: nil) }
    #expect(commonName?.description == "the common name is empty")
    let organization = #expect(throws: Failure.self) { try TLSCommand.subject(commonName: "alpha", organization: "") }
    #expect(organization?.description == "the organization is empty")
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
