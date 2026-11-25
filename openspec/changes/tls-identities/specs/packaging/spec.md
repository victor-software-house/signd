## ADDED Requirements

### Requirement: The app reaches the shared identity group

The app's entitlements SHALL list `com.victor-software-house.identities` as a keychain access group, after signd's own group.
The package and the app SHALL require macOS 27.

#### Scenario: The released app creates an identity

- **WHEN** the released `signd` runs `signd tls create probe` on a Mac
- **THEN** the command succeeds, and `signd key create` still stores SSH keys in signd's own group
