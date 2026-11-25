# Tasks

## 1. Build

- [ ] 1.1 `Package.swift` depends on `swift-daemon-services` 0.0.1 (`KeychainIdentity`), with `swift-nio` 2.105.2, `swift-asn1` 1.7.5 and macOS 27; `project.yml` deploys to macOS 27.
  Verify: CI builds.
- [ ] 1.2 `App/Signd.entitlements` lists the shared group after signd's own.
  Verify: CI's archive succeeds with the entitlements.
- [ ] 1.3 `signd tls create|csr|store|list|remove` in `Sources/SigndCLI`, on `IdentityStore`.
  Verify: CI tests cover argument parsing, the text and JSON listing, and the mismatch error.
- [ ] 1.4 README, `AGENTS.md` invariant 2, the `cli` spec pointer, and a `.changeset` fragment.
  Verify: the docs checks pass in CI.

## 2. On a Mac

- [ ] 2.1 The released build creates, signs with a test authority, stores, lists and removes an identity, and SSH keys still work.
  Verify: `mise run e2e:hardware` with a TLS step passes on a Mac; record the Mac, the release and the date.
