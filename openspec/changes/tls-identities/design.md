# Design

## Context

[KeychainIdentity] keeps a TLS client identity in a keychain access group of the team.
The identity is a Secure Enclave key, the leaf as a certificate item, and the whole chain as one PEM item.

It reads the team from the running code's signature and checks the group against the entitlements.
So it needs a signed app with a provisioning profile.
signd is such an app.

## Decisions

### 1. The commands live in signd

A new signed tool for these five commands would need its own App ID, profile and release.
signd already ships a Developer ID app with a profile, and the `signd` command runs from inside it, so it carries the entitlements.
The logic stays in the library; signd adds argument parsing and output only.

### 2. The commands are generic

signd does not decide a certificate's subject, who signs it, or which hosts receive it.
The caller passes the subject, sends the request to its own authority, and pipes the chain back.
So the same commands serve any authority and any program that presents the identity.

### 3. A separate keychain group

TLS identities go in `com.victor-software-house.identities`, and SSH keys stay in signd's own group.
The operating system then gives another app the TLS identities without giving it the SSH keys.

The shared group comes second in the entitlements, because an item added with no group takes the first one.
signd's SSH key store adds its items that way.
signd's queries already filter by their own service names, so they never read the identity's chain item.

### 4. Local only

A Secure Enclave key cannot leave its Mac, so a TLS identity is never shared through iCloud or backed up.
Each Mac makes its own and gets its own certificate.
The agent neither lists nor signs with TLS identities: only the commands touch them, and the program that presents a certificate reads the group itself.

### 5. macOS 27

The package requires macOS 27, so signd does too.
Both target Macs run macOS 27.2 (checked 2026-11-25).

## Risks

- A Developer ID profile without the shared group fails `signd tls create` with `missingEntitlement`.
  Task 2.1 proves it on a Mac with the released build.

[KeychainIdentity]: https://github.com/victor-software-house/swift-daemon-services/tree/v0.0.1/Sources/KeychainIdentity
