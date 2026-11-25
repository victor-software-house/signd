# Proposal

## Why

A Mac's own tools can need a TLS client identity.
An example is a certificate that a proxy presents to a host that checks client certificates.
Its key should never leave the Mac, and any app of the same team should be able to present it without signd running.

signd is already the signed app that makes Secure Enclave keys on a Mac.
The [swift-daemon-services] package's `KeychainIdentity` library already creates such an identity, builds its signing request and stores its chain.
The change adds the commands only, so a setup script can make an identity, have it signed and store it.

signd does not decide who signs the certificate or which program presents it.

## What Changes

- `signd tls create NAME` makes a Secure Enclave P-256 key in the keychain group `com.victor-software-house.identities`.
- `signd tls csr NAME --common-name CN [--organization O]` prints a certificate signing request for it, in PEM, with that subject.
- `signd tls store NAME` reads a PEM chain, leaf first, from stdin and stores it when its leaf matches the key.
- `signd tls list` shows each identity's name, subject, issuer, expiry and chain length; `--json` prints the same.
- `signd tls remove NAME` deletes the key and its chain.
- The app's entitlements list the shared group after signd's own group, so SSH keys keep their group.
- signd depends on `swift-daemon-services` 0.0.1 and requires macOS 27, as the package does.
  It moves `swift-nio` to 2.105.2 and `swift-asn1` to 1.7.5 to meet the package's floors.
- A TLS identity is never shared through iCloud, never backed up, and never offered by the SSH agent.

## Capabilities

### New Capabilities

- `tls-identities`: the `signd tls` commands and where they keep an identity.

### Modified Capabilities

- `packaging`: the second keychain group and the macOS 27 floor.

## Impact

- Changed files: `Sources/SigndCLI` gets a `TLSCommand` group, and `Package.swift`, `App/Signd.entitlements` and `project.yml` change.
- The Developer ID profile must allow the shared group; a profile that lists `<team>.*` does.
- README, a `.changeset` fragment, and the hardware end-to-end check.

[swift-daemon-services]: https://github.com/victor-software-house/swift-daemon-services
