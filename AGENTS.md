# AGENTS.md

signd is an SSH agent for macOS whose keys only its signed app can use.
It is a Swift 6.4 package.

`SSHEncoding` and `AgentProtocol` contain the SSH encoding and the agent messages, with no platform code.
`KeyStore` contains keys and signing, and `Sync` shares keys between devices through CloudKit.
`AgentServer` contains the agent's state and the SwiftNIO socket server.
The `signd` executable is both the command line and the agent.

`README.md` describes what it does, and `openspec/` describes what it must do.

## 1. Critical invariants

1. No command and no message exports a private key.
2. Stored keys live in the data-protection keychain, in signd's access group.
   TLS identities live in a second group, `com.victor-software-house.identities`, listed after the first.
   Both are readable after first unlock, on this device only.
   The code contains no team identifier, and the entitlements come from the provisioning profile at release time.
3. A signature never runs on the event loop or inside the agent actor.
   It runs on the thread pool, so a slow Secure Enclave call delays no other client.
4. The agent reads at most one bounded message (256 KiB) at a time from a client.
   It answers failure to anything it does not support or cannot parse.
   It closes only that connection on an oversized message.
5. `ssh-add -D` and remove requests touch memory-only keys, never stored ones.
6. signd never uses `Bundle.main`: through the cask's link it has no bundle identifier.
7. Only the agent calls CloudKit, and only when its own signature lists signd's iCloud container.
   The command line sends those requests to the agent.
   A shared key leaves a device only sealed to each device's Secure Enclave key.

## 2. Work in this repository

1. This repository is public: no host names, client names, private repository links, account IDs or personal details in files, commits or pull requests.
2. Changes are planned as OpenSpec changes under `openspec/`; record each task's evidence under it, dated in UTC.
3. Small work items go in the qctl queue, `tasks.yaml`.
4. Builds and tests run in CI, on GitHub-hosted runners.
   Secure Enclave and keychain checks run with `mise run e2e:hardware` on a Mac, since the runners have no Secure Enclave.
5. A pull request that changes behaviour adds a `.changeset` fragment; the Release workflow opens the Version PR and releases each merged version.
6. Installer scripts are one line that runs a `signd` command; their logic is Swift.
7. `App/Signd.entitlements` derives the iCloud container from the bundle identifier.
   The App ID and the profile must list it, and the code reads it from its own signature.
   Xcode builds the bundle from `project.yml`, with `mise run archive` and then `mise run export`.
   `cloudkit/schema.ckdb` declares the CloudKit schema, and `mise run cloudkit:schema` imports it into development.
8. The shared template owns the files `.copier-answers.yml` records; change them through `copier update`, not by hand.
