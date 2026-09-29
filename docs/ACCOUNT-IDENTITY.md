# Account and device identity in v7

An account is a stable namespace derived from CloudKit container, environment and the account's opaque record ID. It groups approved devices and a vault role. It is not a key and does not authorize decryption by itself.

Every device generates independent Secure Enclave agreement and signing keys. Device-only opaque representations live in the provisioned Data Protection Keychain group. App, CLI and AutoFill on that device use the same identity namespace. For another device on the same Apple Account, choose the vaults in Connect This Device and choose Connect. 2ndPass exchanges signed requests and grants automatically through the private iCloud database while an existing owner device is unlocked. No manual approval or comparison screen is involved in this same-account flow. Cross-account sharing still requires independently verified invitations and explicit owner approval.

Same-account enrollment relies on Apple's authenticated iCloud environment plus
code signing, provisioning and CloudKit container entitlements, then on an
owner's signed 2ndPass membership grant. Knowing Apple Account credentials alone
does not authorize arbitrary container writes. An attacker able to operate an
authorized client and access that user's private 2ndPass database may gain
membership if an unlocked, online owner processes the exchange. Avoiding a second
human ceremony is deliberate; no private iCloud Keychain trust-circle API is
queried. See the [full model](SECURITY.md#composed-apple--2ndpass-trust-model).

Cross-account vault sharing is not yet implemented as a supported feature.
Preliminary code would include enrollment in the shared zone; account-private
mailbox isolation is a design detail to address when completing sharing, not a
current product vulnerability. See
[the design review](SECURITY.md#shared-zone-enrollment-exposure).

Device requests bind account scope, ordinary/recovery purpose and both public keys. For manual cross-account sharing and recovery, compare their fingerprints directly with the device. Proof of signing-key possession is not remote attestation that keys were generated in hardware; 2ndPass's own provider requires hardware, but a malicious custom client can submit software public keys. The owner decides which device requests to trust.

The synchronized software-account anchor and key namespace from v5 are not used or deleted. No code for opening those identities is included in the v7 application build graph. See [architecture](VAULT-NEXT.md), [security](SECURITY.md), and [enrollment commands](../README.md).
