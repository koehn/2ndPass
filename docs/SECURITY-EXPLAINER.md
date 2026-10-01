# How 2ndPass protects your secrets

2ndPass protects your passwords with encryption, security hardware built into your
Apple devices, and checks that detect unauthorized changes. Your vault is
encrypted before it reaches iCloud. Each enrolled device has its own protected
keys, so a copy of your encrypted vault is not enough to read your passwords.

These protections work together. Hardware protects the device keys, encryption
protects stored passwords, and signed updates help 2ndPass check who is allowed to
change the vault. Your device security and Apple Account security are important
parts of that protection too.

## Your device keys are protected by hardware

Apple devices supported by 2ndPass have a **Secure Enclave**: an isolated security
component that can use a private key without handing that key to the app.
Think of it as a locked key cabinet that can perform a task for 2ndPass without
letting 2ndPass take the key away.

2ndPass creates its device keys there and does not fall back to ordinary software
keys. The saved information needed to use them is tied to that device; copying
it to another computer does not copy a working set of keys. Apple checks local
authentication before 2ndPass can use the protected keys. While 2ndPass is unlocked, it
can reuse that authorization so you do not need a prompt for every action.

When you reveal or fill a password, 2ndPass decrypts it for that task. This is how a
password manager puts your saved passwords to use. The device's private keys
remain protected by the Secure Enclave throughout the process.

## Your passwords are encrypted separately

Each item has its own randomly generated encryption key, shared by its separately encrypted fields. 2ndPass encrypts a copy
of that small key for each enrolled device. Your list of items has a separate
key, so browsing the list does not require opening every password.

When you ask for one password, 2ndPass uses your device's protected key to unlock
that item's encryption key, then reads the password. It checks the encrypted
data for tampering along the way. Someone who merely obtains your encrypted
cloud data or an encrypted backup does not get the device keys needed to read it.

2ndPass also signs vault updates. A signature lets other devices check that a change
came from a device with the right permissions and follows the history they
already trust. 2ndPass rejects unauthorized changes and conflicting edits rather
than silently accepting them. These checks cannot stop a cloud outage or ensure
that a server always delivers the newest update.

## Adding your devices and sharing with other people

A new device on your Apple Account connects automatically when an existing
owner device has 2ndPass unlocked and can process its request. This makes setup
convenient: you do not need to transfer key files or compare a code.

Apple's [two-factor authentication](https://support.apple.com/en-us/102660) helps
protect new-device sign-ins even when someone knows your account password.
Optional [Apple Account security keys](https://support.apple.com/en-us/102637)
provide extra phishing protection. 2ndPass relies on the system's authenticated
iCloud session; it never collects your Apple Account password or verification
code. These protections help secure automatic enrollment.

**Apple platform security and 2ndPass membership work together.** Apple's code
signing, provisioning and CloudKit entitlements restrict native access to the
2ndPass container; the system's authenticated iCloud context selects your private
database. A new device creates independent Secure Enclave keys and sends a signed
request through that protected namespace. An enrolled owner grants membership
cryptographically. Account credentials alone do not allow arbitrary container
writes. This deliberately avoids repeating Apple's device/account authentication
ceremony; 2ndPass does not directly query Apple's iCloud Keychain trust circle.

An attacker able to operate an authorized 2ndPass client in your Apple environment
and access that private container may request membership. If an unlocked, online
owner processes the exchange, the attacker may gain access to existing secrets.
A compromised bootstrap mailbox could also mislead a new device about which
vault to trust when it first connects. Protect your Apple Account with a strong password and
two-factor authentication, and investigate unfamiliar devices.

Sharing with another person's account requires an explicit invitation,
verification and approval. The owner controls membership. Editors can change
contents; viewers can read them. Accepting an iCloud sharing invitation alone
does not give a device the keys to your passwords.

**Sharing is not yet implemented as a supported feature.** Preliminary code
exists, but the enrollment mailbox must remain private to the owner's account
when sharing is implemented. This is a design detail to address, not a current
product vulnerability. See the
[design review](SECURITY.md#shared-zone-enrollment-exposure).

## Removing a device or person's access

When removal completes, 2ndPass gives the current secrets fresh encryption keys and
leaves the removed recipient out. Their old keys cannot open later protected
versions. Manage enrolled devices in **Settings → devices**. Device removal
covers personal vaults enrolled on the managing device; it is not a universal
revocation across every vault that device may have used.

When an honest removed device reconnects and verifies its removal, 2ndPass clears
its ordinary local identity and account caches. It requires an explicit
**Reconnect** to create fresh keys instead of quietly joining again. A device
that is offline cannot learn about removal immediately.

Removal cannot erase passwords someone already copied or old backups they could
already read. If a password must stop working for that person, change it at the
website or service too. If your Apple Account was compromised, secure the account
as well: an attacker who retains authorized access to the private 2ndPass
container could request enrollment with a new identity.

## What these protections mean in everyday situations

| Situation | How 2ndPass helps |
| --- | --- |
| Someone obtains a copy of your encrypted vault | They still need an authorized device's protected keys to read it. |
| Your locked device is stolen | Device-bound keys and local authentication help prevent access. Someone who can unlock and use your authorized 2ndPass session has a different level of access. |
| Someone alters your stored vault data | Encryption checks and signed updates let 2ndPass reject unauthorized changes against its trusted history. |
| A device or person loses access | Fresh encryption keys protect later versions, while previously copied passwords remain outside 2ndPass's control. |
| You lose your internet connection | You can read a previously trusted local vault after authentication. Offline access cannot learn about a recent removal. |

These protections rely on a trustworthy device, as all password managers do.
Keep your operating system updated and protect your device's unlock credentials;
malware controlling your unlocked device may invoke authorized hardware operations,
observe decrypted item keys and secrets, and capture clipboard, AutoFill or CLI
outputs. Device private keys can remain non-exportable despite that misuse.

## What iCloud and AutoFill can see

2ndPass encrypts passwords, item names and field details. Some information remains
visible to the cloud service, including the vault name, enrolled public
identities, encrypted data sizes and update timing. Choose a vault name you are
comfortable exposing as metadata.

For AutoFill to suggest the right login, 2ndPass supplies Apple’s credential system
with website and username information. That listing does not contain the
password. 2ndPass checks the authenticated vault again before filling it.

## Plan for a lost or broken device

Keep an offline recovery copy separate from your devices and verify it before
you need it. Recovery requires access to the same Apple Account and live cloud
data. See [offline recovery](#offline-recovery-after-device-loss).

## How these protections have been checked

2ndPass's security design uses Apple's hardware key protection and established
cryptographic algorithms. The implementation has been exercised with real
Secure Enclave keys, saved-key reloads and private iCloud storage on a Mac, along
with automated tests for access, tampering, enrollment, removal and recovery.

2ndPass is not yet independently audited. Protocol correctness and implementation
correctness require separate scrutiny; source availability does not replace professional
review. Validation is still in progress. Sharing between two real Apple Accounts,
recovery on separate physical devices, and signed iPhone/iPad and AutoFill
workflows still need the physical-device checks recorded in the
[validation report](VAULT-NEXT-VALIDATION.md). Automated tests and simulator builds
are useful evidence, but do not replace those checks or an independent security
review.

For implementation details and the full threat model, read
[Security and key management](SECURITY.md). The [usage guide](../README.md)
explains setup and recovery commands.

### Item keys in v7

Each item has its own encryption key, shared by its separately encrypted fields.
Opening that key permits access to the whole item. It is not a vault-wide key,
and the app does not retain it between operations. Adding a device wraps existing
item keys for that device; removal replaces keys and ciphertext for all retained
items, including recently deleted items. Old copies cannot be revoked.

## Offline recovery after device loss

Generate and verify an offline recovery copy before losing access to your devices.
On a replacement device, sign into the same Apple Account and import the copy or
enter its code. Read-only recovery can open healthy data while unavailable
attachments postpone completion. Complete each vault to rotate encryption and
remove previous device access. Keep both copies during key replacement until
coverage is complete.

The private recovery secret and copied ciphertext suffice for offline decryption;
protect the copy separately from your devices. It cannot restore Apple Account
access or missing cloud data. Account-loss recovery requires a separately exported
backup; backup restoration is outside this feature. Physical-device acceptance
and cryptographic review remain pending.
