---
"signd": patch
---

`signd tls` makes TLS client identities.
`create` makes a Secure Enclave key, and `csr` prints a signing request for it.
`store` keeps the PEM chain that a certificate authority signed, and `remove` deletes the identity.

The identities have their own keychain group, listed after signd's own in the entitlements.
The SSH agent never offers them.
signd now needs macOS 27.
