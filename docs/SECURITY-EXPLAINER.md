# How Mop protects your secrets

**Onboarding update:** Recovery is optional. A vault starts with one owner device
and no recovery recipient. An authorized owner can add hardware recovery later,
including access to existing secrets. Without a surviving authorized device or
configured recovery device, access is lost. iCloud discovery is an untrusted
enrollment hint, never device approval. No format compatibility layer is used.


Mop gives each approved device its own private keys, generated inside Apple's Secure Enclave. Those private values do not leave the hardware. Your Apple Account helps deliver encrypted data; a new device on that account is enrolled automatically while an existing owner device is unlocked.

Each password has a separate random encryption key. Mop encrypts a copy of that small key for every approved device and any configured recovery device. The item catalog has its own key. Browsing the catalog does not open all password keys; revealing one password opens that password's key only.

The password and its temporary encryption key **do reach Mop's memory**. Commands, clipboard destinations and websites receiving the password also receive plaintext. Apple's APIs protect the device private key operations, not every byte inside the application. Mop releases keys after operations and wipes buffers it owns where practical, but cannot guarantee erasure of every framework or string copy. Compromised authorized code may still ask the hardware to decrypt.

## Approving and removing access

A personal vault is a shared vault with one member account. An owner account controls membership. Editors can change contents; viewers can read. Own-account devices negotiate enrollment automatically through the private iCloud mailbox. Sharing with another account requires explicit invitation and approval. An iCloud share invitation alone cannot decrypt the vault.

Removing a member or device gives current records fresh encryption keys and protects later revisions. It cannot erase a password somebody copied or an old backup they could already decrypt. Change the real password at its website if it must stop working for that person.

Mop checks signed changes against the previous trusted membership. Two concurrent edits cannot silently overwrite each other: one wins and the other must be reviewed against the new revision. Interrupted uploads retain a journal so retrying does not blindly repeat a secret change. Offline browsing is read-only and cannot know about a recent removal.

## Recovery

You can optionally add a separate hardware recovery device and retain encrypted backups. Its public request may be copied; its private keys stay on that device. It can replace lost ordinary devices. If account access is lost, it can recreate a verified backup as a new vault under another account without deleting the source.

If every authorized device and any configured recovery device are lost, your data is unrecoverable. Restoring an Apple Account or possessing an encrypted backup does not recreate those hardware private keys. There is no portable recovery seed or software private-key file.

## What has actually been checked

The implementation has real Secure Enclave, Keychain reload and private-database CloudKit evidence on one Mac, plus automated multi-member/device models. A simulator build or software test cannot prove hardware behavior. Actual second-account sharing, separate physical recovery devices and signed iPhone/iPad/AutoFill behavior still need the checks listed in [validation](VAULT-NEXT-VALIDATION.md).

See [the technical security explanation](SECURITY.md) for API boundaries, memory limits and synchronization details, and [the usage guide](../README.md) for enrollment and recovery commands.

You can remove devices in Settings → devices on Mac, iPhone, or iPad. Mop removes
their wrapped encryption keys and rotates the vault's encryption material.
When a removed device next connects and verifies the removal, it deletes its
local device identity and account caches. It asks whether you want to reconnect;
it does not quietly join again. Reconnect creates fresh device keys. Removal
cannot erase previously copied passwords or notify a device that is offline.
