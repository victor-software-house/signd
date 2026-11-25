# Changelog

## signd 0.0.20

- `signd tls` makes TLS client identities.
  `create` makes a Secure Enclave key, and `csr` prints a signing request for it.
  `store` keeps the PEM chain that a certificate authority signed, and `remove` deletes the identity ([`4002eee`](https://github.com/victor-software-house/signd/commit/4002eee192b1ecb2deb8552bcd81e75f5ddadb81)).

  The identities have their own keychain group, listed after signd's own in the entitlements.
  The SSH agent never offers them.
  signd now needs macOS 27.

## signd 0.0.19

- Command messages read as plain English.
  After an update, `signd update` prints `updated signd from 0.0.17 to 0.0.18 and restarted the agent`.
  A later run within 5 minutes prints `signd is up to date`, with the versions and the time of the update.
  When the updater cannot be reached, the error gives the command that fixes it.
  `signd status` shows the agent as `running` or `not running` ([`d46233a`](https://github.com/victor-software-house/signd/commit/d46233a00d05f2e9df81ddd8cb8f72bc4f3a82d7)).

## signd 0.0.18

- On a terminal, signd marks each result with a coloured symbol and colours the values of `signd status`.
  The new `--color auto|always|never` option, `NO_COLOR` and `CLICOLOR_FORCE` set it, and piped output stays plain ([`2b6cbf6`](https://github.com/victor-software-house/signd/commit/2b6cbf6769e4fcd4af374cf34b97781d9db72e64)).

## signd 0.0.17

- `signd backup restore` reads the private key, hosts and comment of an item again.
  A backup run writes only the key items that changed.
  1Password gives a field outside every named section an empty section ID, and signd took that field for a field of another section ([`571ead0`](https://github.com/victor-software-house/signd/commit/571ead0e21699ef773f9dc682100106da8ccc9a0)).

## signd 0.0.16

- A changed backup setting now applies at once: `signd config set` and `unset` notify the running agent, which computes the wait for the next backup again.
  `signd backup status` shows the time the agent waits for ([`9d211e0`](https://github.com/victor-software-house/signd/commit/9d211e0b16f107418f43653e32cdc0f88775ee45)).

## signd 0.0.15

- `signd update` checks for a newer release now, installs it, restarts the agents on it, and prints the result ([`c6423c3`](https://github.com/victor-software-house/signd/commit/c6423c321b146f4a4e7887aa60c6eb2d61043a5f)).

  `signd status` shows whether updates are on, the interval and its source, and the last update check.

  `signd updater` is the launch daemon's own command, hidden from `--help`: it checks on a schedule as root and answers `signd update`.

  The package installs the updater daemon in `/Library/LaunchDaemons` and loads it, and each release attaches the stapled `Signd.app.zip` that the updater downloads.

## signd 0.0.14

- `signd backup restore` lists the keys of the 1Password backup, and restores the ones named or all with `--all`.
  A restored key is shared with every Mac, or stays on this one with `--local` ([`039e66b`](https://github.com/victor-software-house/signd/commit/039e66b3c032b056f41bcefc15bb1b4000d86698)).

  `signd status` and `signd backup status` show whether the backup is on, its last run and its next run.

## signd 0.0.13

- The agent now copies shared keys, this Mac's own keys and a list of its Secure Enclave keys to the 1Password vault.
  It starts once a backup token is stored ([`d90d943`](https://github.com/victor-software-house/signd/commit/d90d94311747485793554788b812c419fb3f3ba2)).

  A run starts 5 minutes after the last key change, at most once an hour, and once a day with no change.
  Only one Mac runs the backup at a time.

  The new `backup-delay`, `backup-min-interval` and `backup-max-interval` settings change the three times.
- The app icon's seal fills more of its square, so it reads larger in Finder and Login Items ([`e13a0b7`](https://github.com/victor-software-house/signd/commit/e13a0b796421b6fad4a6e6c9c2ce869fd957c0bc)).
- Each release attaches `signd.mobileconfig`, an example profile for a Mobile Device Management (MDM) server.
  The package also installs a login hook.
  An admin who pushes both gets the agent for every user at login, with no approval prompt ([`28cf760`](https://github.com/victor-software-house/signd/commit/28cf760c4da9795a56fed43d06714e128ba41cb5)).

  A user on a Mac with no profile sees nothing new.
  The hook exits at once when the agent runs, and never opens System Settings.

## signd 0.0.12

- The new `backup-removed` setting chooses whether the 1Password backup deletes, archives or keeps the item of a removed key.
  It defaults to delete ([`eb94ffa`](https://github.com/victor-software-house/signd/commit/eb94ffa8dbf4295004461fdd3e3b6d8dc0344fae)).
- Signd.app has an app icon.
  The repository builds the app target with XcodeGen and Xcode, and every pull request checks that build ([`e4092b8`](https://github.com/victor-software-house/signd/commit/e4092b83a54ac2dfebba4064d8c8b51a750e5ea7)).
- The release builds Signd.app with Xcode.
  It exports the app signed with the Developer ID profile ([`9cca26b`](https://github.com/victor-software-house/signd/commit/9cca26bbf9f545e56c902820fa518d743b4c5907)).

## signd 0.0.11

- `signd backup login` reads a 1Password service account token from stdin.
  It checks that the account lists the vault named by the `backup-vault` setting.
  Then it stores the token on every Mac, sealed to each Mac's Secure Enclave key.
  `signd backup logout` deletes it on every Mac ([`3ea5976`](https://github.com/victor-software-house/signd/commit/3ea5976b4ed38b1c1b4f0be97ccf307213f924c7)).

## signd 0.0.10

- A package installed over a running agent takes effect at once.
  `signd service enable` restarts an agent that reports another version ([`beb9d21`](https://github.com/victor-software-house/signd/commit/beb9d21ca186d5d3cf72c89aca4ca1d4716d4297)).

## signd 0.0.9

- The package links `signd` into `/usr/local/bin`, and `signd service enable` adds `Include ~/.ssh/signd/config` to the top of `~/.ssh/config`.
  `signd status` shows the login item and that line, and `signd service` gains `status`, `restart` and `log`.
  The package opens with its own welcome, license and conclusion pages, and only on an Apple silicon Mac with macOS 26 or later ([`2befd54`](https://github.com/victor-software-house/signd/commit/2befd54dbf041306d1dd04cb1c1281eb4e90457c)).

## signd 0.0.8

- The release signs Signd.app with the iCloud and push entitlements that the iCloud sync needs; 0.0.7 built no package ([`71c9abd`](https://github.com/victor-software-house/signd/commit/71c9abd011b9806c32f5fb5925ea1e11bf39247d)).
- The release edits Signd.app's entitlements with PlistBuddy. PlistBuddy reads the dots in an entitlement name as part of the name, so no key path needs escaping ([`f9f51c8`](https://github.com/victor-software-house/signd/commit/f9f51c8fbe1fdaf1d5752922c870eeabe384fa60)).

## signd 0.0.7

- signd shares keys between the Macs of one Apple account through iCloud, in place of 1Password. A key created or imported on one Mac is sealed to every Mac's Secure Enclave key and reaches the others within a few seconds; `--local` keeps a key on its Mac. New commands: `signd key share`, `signd device list` and `signd device remove`. `signd login` and `signd logout` are gone, and the `interval` setting now defaults to 2 seconds ([`46fa782`](https://github.com/victor-software-house/signd/commit/46fa7820fc09a101894be29077f17b690e82c4c6)).

## signd 0.0.6

- signd keeps a synced key when 1Password's reply for its item cannot be read, reads such an item again after an upgrade, and reports a local setting that is out of bounds in `signd status`.
  A lasting name conflict costs one request a check, and only the signd command line may use signd's private extensions ([`104e269`](https://github.com/victor-software-house/signd/commit/104e269658f9e328b4d2edf96f527b28b150e6a0)).

## signd 0.0.5

- signd syncs SSH keys from 1Password with only a service account token.
  `signd login` stores the token, `signd logout` removes it with the synced keys, `signd sync` checks now, and `signd status` shows the last check, the next and the skipped items.
  Keys with hosts are routed through `~/.ssh/signd/config` ([`3752060`](https://github.com/victor-software-house/signd/commit/375206058e61ee2783b38fcfd06993a687f92881)).

## signd 0.0.4

- The package starts the agent after it installs, so an upgrade through the cask no longer leaves the agent stopped ([`5276a55`](https://github.com/victor-software-house/signd/commit/5276a559370c9485e5bd885b2e1c5c5a5f912848)).

## signd 0.0.3

- `signd service enable` starts the agent again when its login item is enabled but launchd no longer runs it, as after a cask upgrade ([`c4afb96`](https://github.com/victor-software-house/signd/commit/c4afb96a43544f39f764d1005235f30db744672d)).
- `signd key import NAME FILE` brings an existing Ed25519, ECDSA or RSA private key into signd, from a file or from stdin, and asks for the passphrase of a protected file through `ssh-add`.
  `signd key create NAME --type ed25519|rsa-3072|rsa-4096` makes such a key, and both seal it to its own Secure Enclave key so that only signd can use it ([`5e54fb9`](https://github.com/victor-software-house/signd/commit/5e54fb9c84d580a4da22866d709448b0c5640783)).

## signd 0.0.2

- signd is licensed under the GNU Affero General Public License, version 3 ([`8249951`](https://github.com/victor-software-house/signd/commit/82499516f3096ae3c509059b5a756ab17fed6dbe)).
- keychain-agent becomes signd, an SSH agent for keys only its signed app can use.
  `signd key create` makes Secure Enclave P-256 keys, held in signd's data-protection keychain access group, and `signd service enable` runs the agent at login on `~/.ssh/signd.sock`.
  The agent also accepts memory-only keys from `ssh-add`, with lifetimes, and never lets `ssh-add -D` remove a stored key ([`4ff038c`](https://github.com/victor-software-house/signd/commit/4ff038c2ccbccd6beeb832de96ba4741aa7291ca)).

## keychain-agent 0.0.1

- The first release of keychain-agent, an SSH agent for RSA keys held non-extractable in the login keychain, as a signed and notarized `keychain-agent.pkg` that installs `/usr/local/bin/keychain-agent`.

