# How Mop protects your secrets

Mop protects your passwords with encryption, security hardware built into your
Apple devices, and checks that detect unauthorized changes. Your vault is
encrypted before it reaches iCloud. Each enrolled device has its own protected
keys, so a copy of your encrypted vault is not enough to read your passwords.

These protections work together. Hardware protects the device keys, encryption
protects stored passwords, and signed updates help Mop check who is allowed to
change the vault. Your device security and Apple Account security are important
parts of that protection too.

## Your device keys are protected by hardware

Apple devices supported by Mop have a **Secure Enclave**: an isolated security
component that can use a private key without handing that key to the app.
Think of it as a locked key cabinet that can perform a task for Mop without
letting Mop take the key away.

Mop creates its device keys there and does not fall back to ordinary software
keys. The saved information needed to use them is tied to that device; copying
it to another computer does not copy a working set of keys. Apple checks local
authentication before Mop can use the protected keys. While Mop is unlocked, it
can reuse that authorization so you do not need a prompt for every action.

When you reveal or fill a password, Mop decrypts it for that task. This is how a
password manager puts your saved passwords to use. The device's private keys
remain protected by the Secure Enclave throughout the process.

## Your passwords are encrypted separately

Each secret has its own randomly generated encryption key. Mop encrypts a copy
of that small key for each enrolled device. Your list of items has a separate
key, so browsing the list does not require opening every password.

When you ask for one password, Mop uses your device's protected key to unlock
that password's encryption key, then reads the password. It checks the encrypted
data for tampering along the way. Someone who merely obtains your encrypted
cloud data or an encrypted backup does not get the device keys needed to read it.

Mop also signs vault updates. A signature lets other devices check that a change
came from a device with the right permissions and follows the history they
already trust. Mop rejects unauthorized changes and conflicting edits rather
than silently accepting them. These checks cannot stop a cloud outage or ensure
that a server always delivers the newest update.

## Adding your devices and sharing with other people

A new device on your Apple Account connects automatically when an existing
owner device has Mop unlocked and can process its request. This makes setup
convenient: you do not need to transfer key files or compare a code.

**Your Apple Account is part of this security boundary.** Someone who gains
control of the account's private iCloud mailbox could enroll their own device
while your existing Mop session is unlocked and gain access to your vault.
A compromised mailbox could also mislead a new device about which vault to trust
when it first connects. Protect your Apple Account with a strong password and
two-factor authentication, and investigate unfamiliar devices.

Sharing with another person's account requires an explicit invitation,
verification and approval. The owner controls membership. Editors can change
contents; viewers can read them. Accepting an iCloud sharing invitation alone
does not give a device the keys to your passwords.

## Removing a device or person's access

When removal completes, Mop gives the current secrets fresh encryption keys and
leaves the removed recipient out. Their old keys cannot open later protected
versions. Manage enrolled devices in **Settings → devices**. Device removal
covers personal vaults enrolled on the managing device; it is not a universal
revocation across every vault that device may have used.

When an honest removed device reconnects and verifies its removal, Mop clears
its ordinary local identity and account caches. It requires an explicit
**Reconnect** to create fresh keys instead of quietly joining again. A device
that is offline cannot learn about removal immediately.

Removal cannot erase passwords someone already copied or old backups they could
already read. If a password must stop working for that person, change it at the
website or service too. If your Apple Account was compromised, secure the account
as well: an attacker who retains access could request enrollment with a new
identity.

## What these protections mean in everyday situations

| Situation | How Mop helps |
| --- | --- |
| Someone obtains a copy of your encrypted vault | They still need an authorized device's protected keys to read it. |
| Your locked device is stolen | Device-bound keys and local authentication help prevent access. Someone who can unlock and use your authorized Mop session has a different level of access. |
| Someone alters your stored vault data | Encryption checks and signed updates let Mop reject unauthorized changes against its trusted history. |
| A device or person loses access | Fresh encryption keys protect later versions, while previously copied passwords remain outside Mop's control. |
| You lose your internet connection | You can read a previously trusted local vault after authentication. Offline access cannot learn about a recent removal. |

These protections rely on a trustworthy device, as all password managers do.
Keep your operating system updated and protect your device's unlock credentials;
malware controlling your device can capture passwords when you use them.

## What iCloud and AutoFill can see

Mop encrypts passwords, item names and field details. Some information remains
visible to the cloud service, including the vault name, enrolled public
identities, encrypted data sizes and update timing. Choose a vault name you are
comfortable exposing as metadata.

For AutoFill to suggest the right login, Mop supplies Apple’s credential system
with website and username information. That listing does not contain the
password. Mop checks the authenticated vault again before filling it.

## Plan for a lost or broken device

You can add a separate hardware recovery device and keep encrypted backups.
Recovery is optional; a new vault starts without it. A configured recovery device
can help restore access, including moving a verified backup to a new account if
necessary. Because it can unlock your secrets, keep it secure and separate from
your everyday device.

**If you lose every enrolled device and every configured recovery device, your
vault cannot be recovered.** Restoring your Apple Account or finding an encrypted
backup does not recreate the hardware keys. There is no recovery seed or hidden
master key that bypasses this protection.

## How these protections have been checked

Mop's security design uses Apple's hardware key protection and established
cryptographic algorithms. The implementation has been exercised with real
Secure Enclave keys, saved-key reloads and private iCloud storage on a Mac, along
with automated tests for access, tampering, enrollment, removal and recovery.

Validation is still in progress. Sharing between two real Apple Accounts,
recovery on separate physical devices, and signed iPhone/iPad and AutoFill
workflows still need the physical-device checks recorded in the
[validation report](VAULT-NEXT-VALIDATION.md). Automated tests and simulator builds
are useful evidence, but do not replace those checks or an independent security
review.

For implementation details and the full threat model, read
[Security and key management](SECURITY.md). The [usage guide](../README.md)
explains setup and recovery commands.
