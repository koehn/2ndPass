# Account and device identity in v6

An account is a stable namespace derived from CloudKit container, environment and the account's opaque record ID. It groups approved devices and a vault role. It is not a key and does not authorize decryption by itself.

Every device generates independent Secure Enclave agreement and signing keys. Device-only opaque representations live in the provisioned Data Protection Keychain group. App, CLI and AutoFill on that device use the same identity namespace. For another device on the same Apple Account, choose the vaults in Connect This Device and choose Connect. Mop exchanges signed requests and grants automatically through the private iCloud database while an existing owner device is unlocked. No manual approval or comparison screen is involved in this same-account flow. Cross-account sharing still requires independently verified invitations and explicit owner approval.

Device requests bind account scope, ordinary/recovery purpose and both public keys. For manual cross-account sharing and recovery, compare their fingerprints directly with the device. Proof of signing-key possession is not remote attestation that keys were generated in hardware; Mop's own provider requires hardware, but a malicious custom client can submit software public keys. The owner decides which device requests to trust.

The synchronized software-account anchor and key namespace from v5 are not used or deleted. No code for opening those identities is included in the v6 application build graph. See [architecture](VAULT-NEXT.md), [security](SECURITY.md), and [enrollment commands](../README.md).
