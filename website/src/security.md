---
layout: guide.njk
permalink: security.html
title: Security
description: "How 2ndPass protects secrets, what iCloud is trusted with, and the limits you should understand."
eyebrow: Security, explained
heading: "Know what you’re trusting."
intro: "Hardware-protected device keys. Encryption before sync. Explicit boundaries, including the uncomfortable ones."
toc:
  - {id: encryption, label: Encryption & keys}
  - {id: attacks, label: Common attacks}
  - {id: icloud, label: iCloud & account trust}
  - {id: devices, label: Devices & sharing}
  - {id: recovery, label: Recovery}
  - {id: local, label: Local exposure}
  - {id: practices, label: Good habits}
  - {id: status, label: Validation status}
---
## Encryption

Each enrolled device creates separate P-256 private keys for decryption and signing in its Secure Enclave. Those private keys are non-exportable: the app asks the hardware to perform operations without extracting them. Each item has its own symmetric key for its separately encrypted fields; a separately encrypted catalog protects item organization and metadata within the vault.

2ndPass uses authenticated encryption and HPKE (`P256_SHA256_AES_GCM_256`) to wrap secret keys for authorized devices. Signed revisions and verified checkpoints help clients detect tampering and rollback relative to the state they already trust. Vault contents are encrypted locally before they leave the device.

**Secure Enclave protection is not a promise that plaintext never enters memory.** Derived key material and decrypted secrets are used in the app’s process. A compromised, unlocked device or malicious software with sufficient privileges can still expose them. The enclave protects the device’s private key, not everything an application does with a password.

The [security design](https://github.com/koehn/2ndPass/blob/main/docs/SECURITY.md) and [vault protocol](vault.html) describe the algorithms, checks, and trust model in detail.

## Attacks

### Stolen files, backups, or cloud data

Vault contents are encrypted before storage or upload. Item keys are wrapped for authorized devices, whose private keys stay in the Secure Enclave. The app stores device-bound key representations in the non-synchronizing Keychain and requires local authentication to use them. A copied encrypted vault does not provide a master-password hash to crack or a portable private key. Plaintext exports and some metadata, including vault names and record sizes, are outside this protection.

### Reading application memory

2ndPass decrypts concealed fields when needed, rather than keeping every password decrypted. Its unlocked read cache contains encrypted records and the decoded catalog, not revealed passwords or unwrapped item keys. It wipes owned secret buffers when released and clears session state and hardware-key handles on lock. Passwords and temporary decryption keys still enter memory during use: malware controlling the app or operating system can capture them, and not every copy made by the UI or system frameworks can be reliably erased.

### Modified binaries and injected code

Apple code signing, provisioning, and Keychain access groups protect access to the device identity. On macOS, 2ndPass also checks its signing identity and requires hardened-runtime protections with debugger access and library-validation bypasses disabled. Simply modifying or re-signing the app does not grant an attacker the legitimate app's Keychain access. These protections rely on the operating system; they do not make malicious code with an accepted signing identity safe, and enrollment does not remotely verify which binary another device runs.

### Tampered or replayed cloud records

Authenticated encryption detects altered ciphertext. Signed revisions and locally trusted checkpoints help reject unauthorized updates and rollback against known history. They cannot force a server to deliver the latest data or remain available. Account takeover is a separate threat because the Apple Account participates in new-device enrollment, as explained below.

### Clipboard and screen capture

Passwords are concealed until requested, revealed values hide again after a timeout, and secret clipboard copies stay local to the device and expire. Locking hides vault contents and clears the app's unchanged clipboard copy. These measures limit exposure, but cannot erase a password another application or screen capture has already obtained.

## iCloud

CloudKit provides transport and storage through your Apple Account. There is no separate 2ndPass-hosted vault service. Secret contents are encrypted by 2ndPass before upload; iCloud carries the ciphertext and encrypted key material.

**Your Apple Account is part of the trust boundary.** For your own devices, an enrolled owner device can automatically approve a new device through the account’s private iCloud mailbox while the owner app is unlocked. Someone who compromises that account may be able to enroll an attacker-controlled device during that window. Protect the account and its trusted devices accordingly.

Encryption does not conceal all metadata. Cloud records can expose vault names, public identities, record sizes, and timing. The local AutoFill index and Apple’s suggestion system receive website, username, and opaque identifier metadata. Passwords and OTP seeds are not placed in that index.

Offline reads require a previously verified local checkpoint. They cannot establish current server freshness or discover a revocation that happened after the device went offline. Writes require connectivity.

## Devices

Each authorized device has its own hardware key. Sharing with someone on another Apple Account requires an invitation, acceptance, identity verification, and owner approval. An iCloud share invitation alone does not supply the decryption keys. Viewer and editor roles control access within the vault protocol.

Removing a device or member rotates current encryption keys. It cannot erase plaintext someone already copied or make old backups disappear. If a removed member knew a service password, rotate that password at the service too.

Cross-account sharing needs further physical acceptance testing before release. See the current [validation status](#status).

## Recovery

A separate hardware recovery device is optional. Set it up while you still have a working owner device, compare its fingerprint independently, and store it separately. An encrypted backup preserves data; it is not a substitute for surviving authorized hardware.

**If every authorized device and every configured recovery device is lost, the vault is unrecoverable.** Restoring an Apple Account or downloading a backup does not recreate Secure Enclave private keys. There is no vendor password-reset back door.

Follow the [recovery guide](docs.html#recovery), including checkpoint verification. Separate-device recovery acceptance remains outstanding; do not make an untested recovery path your only plan.

## Local

The app conceals sensitive fields and uses authentication to unlock access. AutoFill uses a fresh authentication session for each fill. These controls reduce accidental exposure; they cannot make a compromised operating system safe.

The CLI deliberately releases plaintext where you ask it to:

- `read` writes a secret to standard output.
- `run` gives resolved secrets to a child process through its environment. Default output masking matches exact secret bytes; transformed output, files, and network traffic are outside that protection.
- `inject` writes literal values into generated configuration. It does not escape values for the destination format.
- Attachment exports and password-manager import files contain plaintext.

Treat those outputs as credentials. Removing a temporary file is ordinary deletion, not a guarantee of secure erasure. Shell history, logs, screen sharing, backups, and a child process can all create additional copies.

## Practices

1. Protect your Apple Account, its recovery channels, and trusted devices. Review unfamiliar devices promptly.
2. Keep macOS/iOS and 2ndPass current. Lock your device and the app when you step away.
3. Use distinct, generated passwords. Enable service-level multi-factor authentication where available.
4. Keep references in project files and actual secrets out of source control. Review programs before handing them credentials.
5. Verify imports and their warnings. Remove unwanted plaintext exports and check where they may have been backed up.
6. Maintain separate recovery hardware and encrypted backups. Record trusted checkpoints independently and test the documented recovery process.
7. Verify a recipient’s identity before approving access. Rotate service credentials when revocation must also invalidate copied passwords.

## Status

**2ndPass is a development preview, not an independently audited release.** Automated tests and Mac hardware checks are useful evidence, but they are not a substitute for external review or full device acceptance.

Outstanding release gates include an independent security audit, sharing between two actual Apple Accounts, recovery on separate physical hardware, and signed iOS/AutoFill acceptance on physical devices. Simulator builds do not verify Secure Enclave behavior.

Keep your existing password manager and a verified recovery route while evaluating the project. The [v7 validation record](vault-validation.html) documents completed checks, measurements, and remaining live acceptance work as of September 27, 2026.
