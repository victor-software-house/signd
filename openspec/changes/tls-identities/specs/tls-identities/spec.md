## ADDED Requirements

### Requirement: signd makes TLS client identities

`signd tls create NAME` SHALL create a Secure Enclave P-256 key in the keychain group `com.victor-software-house.identities`.
`signd tls csr NAME --common-name CN [--organization O]` SHALL print a certificate signing request in PEM, signed by that key.
Its subject SHALL be the common name, and the organization when given.

#### Scenario: A name in use

- **WHEN** `signd tls create mirror` runs while an identity named `mirror` exists
- **THEN** the command fails and changes nothing

### Requirement: signd stores and removes a TLS identity

`signd tls store NAME` SHALL read a PEM chain, leaf first, from stdin, and SHALL store it only when the leaf's public key is the identity's key.
`signd tls remove NAME` SHALL delete the key and its chain.

#### Scenario: Create, sign and store

- **WHEN** `signd tls create mirror` runs, then `signd tls csr mirror --common-name test` is signed by a test authority, and the chain is piped to `signd tls store mirror`
- **THEN** `signd tls list` shows `mirror` with subject `CN=test`, the authority as issuer, and a chain of 2

#### Scenario: A chain for another key

- **WHEN** `signd tls store mirror` reads a chain whose leaf contains another key
- **THEN** the command fails, names the mismatch, and stores nothing

### Requirement: TLS identities stay on the Mac and out of the agent

signd SHALL NOT share a TLS identity through iCloud, back it up, or offer it through the SSH agent.

#### Scenario: The agent does not list it

- **WHEN** `signd tls create mirror` has run
- **THEN** `ssh-add -L` lists no key for it, and `signd key list` does not show it

### Requirement: The listing reads as text or JSON

`signd tls list` SHALL show each identity's name, subject, issuer, expiry and chain length, and `--json` SHALL print the same fields as one JSON document.
An identity with no chain yet SHALL show as waiting for a certificate.

#### Scenario: Before the chain is stored

- **WHEN** `signd tls create mirror` has run and no chain was stored
- **THEN** `signd tls list --json` shows `mirror` with no subject and no expiry
