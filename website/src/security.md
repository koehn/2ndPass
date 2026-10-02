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

Each enrolled device creates separate P-256 private keys for decryption and signing in its Secure Enclave. Those independently generated, hardware-bound device identity keys are non-exportable: the app holds opaque references and asks the Secure Enclave to perform operations without exposing private key material to normal application memory. Each item has its own symmetric key for its separately encrypted fields; a separately encrypted catalog protects item organization and metadata within the vault.

2ndPass uses authenticated encryption and HPKE (`P256_SHA256_AES_GCM_256`) to wrap secret keys for authorized devices. Signed revisions and verified checkpoints help clients detect tampering and rollback relative to the state they already trust. Vault contents are encrypted locally before they leave the device.

**Secure Enclave protection is not a promise that plaintext never enters memory.** Derived key material and decrypted secrets are used in the app’s process. A compromised, unlocked device or malicious software with sufficient privileges can invoke authorized key operations and capture their plaintext results even when the device private key remains non-exportable. The enclave protects the device’s private key, not everything an application does with a password.

Apple Passwords/iCloud Keychain also uses substantial Secure Enclave-backed protection; see Apple's [Keychain security documentation](https://support.apple.com/guide/security/secb0694df1a/web). 2ndPass's distinction is its explicit, inspectable device-identity and item-key protocol, not exclusive use of Apple security hardware or a claim of greater security. Apple's system is integrated deeper into the OS and its complete implementation is not publicly inspectable.

The [security design](https://github.com/koehn/2ndPass/blob/main/docs/SECURITY.md) and [vault protocol](vault.html) describe the algorithms, checks, and trust model in detail.

## Attacks

### Stolen files, backups, or cloud data

Vault contents are encrypted before storage or upload. Item keys are wrapped for authorized devices, whose private keys stay in the Secure Enclave. The app stores device-bound key representations in the non-synchronizing Keychain and requires local authentication to use them. A copied encrypted vault does not provide a master-password hash to crack or a portable private key. Copying local storage or the opaque Keychain representation cannot reconstruct the device private key on another machine. Plaintext exports and some metadata, including vault names and record sizes, are outside this protection.

### Reading application memory

2ndPass decrypts concealed fields when needed, rather than keeping every password decrypted. Its unlocked read cache contains encrypted records and the decoded catalog, not revealed passwords or unwrapped item keys. It wipes owned secret buffers when released and clears session state and hardware-key handles on lock. Passwords and temporary decryption keys still enter memory during use: malware controlling the app or operating system can capture them, and not every copy made by the UI or system frameworks can be reliably erased.

### Modified binaries and injected code

Apple code signing, provisioning, and Keychain access groups protect access to the device identity. On macOS, 2ndPass also checks its signing identity and requires hardened-runtime protections with debugger access and library-validation bypasses disabled. Simply modifying or re-signing the app does not grant an attacker the legitimate app's Keychain access. These protections rely on the operating system; they do not make malicious code with an accepted signing identity safe, and enrollment does not remotely verify which binary another device runs.

### Tampered or replayed cloud records

Authenticated encryption detects altered ciphertext. Signed revisions and locally trusted checkpoints help reject unauthorized updates and rollback against known history. They cannot force a server to deliver the latest data or remain available. Checkpoints depend on intact local trust state; restoring older local state can remove evidence of a rollback. Account takeover is a separate threat because the Apple Account participates in new-device enrollment, as explained below.

### Clipboard and screen capture

Passwords are concealed until requested, revealed values hide again after a timeout, and secret clipboard copies stay local to the device and expire. Locking hides vault contents and clears the app's unchanged clipboard copy. These measures limit exposure, but cannot erase a password another application or screen capture has already obtained.

## iCloud

CloudKit provides transport and storage through your Apple Account. There is no separate 2ndPass-hosted vault service. Secret contents are encrypted by 2ndPass before upload; iCloud carries the ciphertext and encrypted key material.

Apple protects account sign-in with [two-factor authentication](https://support.apple.com/en-us/102660), enabled by default for most accounts: a new device requires the account password and verification through a trusted device or phone number. Optional [Security Keys for Apple Account](https://support.apple.com/en-us/102637) add protection against phishing. 2ndPass uses the system's authenticated iCloud session and never asks for your Apple Account password or verification code. These account security keys are separate from 2ndPass's offline recovery copy.

**Apple and 2ndPass provide different layers of the trust model.** Apple authenticates the iCloud environment; code signing, provisioning and CloudKit entitlements restrict native client access to the 2ndPass container and its private per-user database. A new device creates its own Secure Enclave identity, submits a signed request through that namespace, and receives item-key envelopes only after an enrolled owner device publishes a signed membership grant. See Apple's [container access](https://developer.apple.com/documentation/cloudkit/ckcontainer) and [private database](https://developer.apple.com/documentation/cloudkit/ckcontainer/privateclouddatabase) documentation.

Ordinary same-account enrollment deliberately reuses Apple's account/device authentication and authorized app access without adding another comparison ceremony. It does not directly query or join Apple's private iCloud Keychain trust circle. Platform sandboxing also contributes on iOS/iPadOS. The Mac app and AutoFill extension enable App Sandbox; the app permits outbound network connections and user-selected file access. The separately installed Mac CLI remains unsandboxed for developer workflows. The Mac packages also use the hardened runtime and restricted entitlements.

**Residual enrollment threat:** an attacker with enough control of your Apple environment to operate an authorized 2ndPass client and access your private 2ndPass container may submit a valid request. If an enrolled owner session processes the exchange while unlocked and online, that identity may receive owner membership and access to existing secrets. Apple Account credentials alone do not permit arbitrary writes into this container. Compromise of the bootstrap mailbox could also substitute a new device's initial trust root; existing devices still check against their previously trusted history.

Encryption does not conceal all metadata. Cloud records can expose vault names, public identities, record sizes, and timing. The local AutoFill index and Apple’s suggestion system receive website, username, and opaque identifier metadata. Passwords and OTP seeds are not placed in that index.

Offline reads require a previously verified local checkpoint. They cannot establish current server freshness or discover a revocation that happened after the device went offline. Writes require connectivity.

## Devices

Each authorized device has its own hardware key. Sharing with someone on another Apple Account requires an invitation, acceptance, identity verification, and owner approval. An iCloud share invitation alone does not supply the decryption keys. Viewer and editor roles control access within the vault protocol.

Removing a device or member generates fresh per-item keys, rewrites all retained field ciphertext (including recently deleted items and attachments), and excludes the removed recipient from the new key envelopes. The catalog also gets a fresh key. Adding a device wraps existing item keys; a role-only change does not rotate them. Removal cannot erase plaintext, retained keys, or historical ciphertext a recipient could already decrypt. If a removed member knew a service password, rotate that password at the service too.

Cross-account vault sharing is not yet implemented as a supported feature.
Preliminary sharing code places enrollment in the zone it would share with other
accounts. Keeping that mailbox account-private is a design detail to address
when implementing sharing, followed by controlled two-account validation. This
is an unfinished-feature design issue, not a current product vulnerability. See
the [design review](https://github.com/koehn/2ndPass/blob/main/docs/SECURITY.md#shared-zone-enrollment-exposure).

## Recovery

Generate and verify an offline recovery copy before losing access to your devices.
On a replacement device, sign into the same Apple Account and import the copy or
enter its code. Read-only recovery can open healthy data while unavailable
attachments postpone completion. Complete each vault to rotate encryption and enroll the replacement device while
preserving existing devices, accounts, and roles. Keep both copies during key replacement until
coverage is complete.

The private recovery secret and copied ciphertext suffice for offline decryption;
protect the copy separately from your devices. It cannot restore Apple Account
access or missing cloud data. Account-loss recovery requires a separately exported
backup; backup restoration is outside this feature. Physical-device acceptance
and cryptographic review remain pending.

## Local

The app conceals sensitive fields and uses authentication to unlock access. AutoFill uses a fresh authentication session for each fill. These controls reduce accidental exposure; they cannot make a compromised operating system safe.

The CLI deliberately releases plaintext where you ask it to:

- `read` writes a plaintext secret to standard output or the requested file.
- `run` gives resolved secrets to a child process through its environment. Default output masking matches exact secret bytes; transformed output, files, and network traffic are outside that protection.
- `inject` writes literal plaintext values to stdout or generated configuration files. It does not escape values for the destination format.
- Attachment exports and password-manager import files contain plaintext.

The child process, its dependencies and descendants receiving the environment become trusted with the secret. Environment variables can leak through the program itself, diagnostics or privileged host access; they are not a secure container. 2ndPass cannot control what an arbitrary child does with plaintext. This disclosure is necessary for developer-secret automation.

AutoFill shares the app's provisioned Keychain group and device identity, but requires its own fresh authentication. Its extension and the receiving app/site are also within the plaintext trust boundary.

Treat those outputs as credentials. Removing a temporary file is ordinary deletion, not a guarantee of secure erasure. Shell history, logs, screen sharing, backups, and a child process can all create additional copies.

## Practices

1. Protect your Apple Account, its recovery channels, and trusted devices. Review unfamiliar devices promptly.
2. Keep macOS/iOS and 2ndPass current. Lock your device and the app when you step away.
3. Use distinct, generated passwords. Enable service-level multi-factor authentication where available.
4. Keep references in project files and actual secrets out of source control. Review programs before handing them credentials.
5. Verify imports and their warnings. Remove unwanted plaintext exports and check where they may have been backed up.
6. Keep an offline recovery copy separate from your devices and test same-account recovery. Keep both copies until key replacement finishes. Backups address missing cloud data and account loss separately.
7. Verify a recipient’s identity before approving access. Rotate service credentials when revocation must also invalidate copied passwords.

## Status

**2ndPass is a development preview, not an independently audited release.** Automated tests and Mac hardware checks are useful evidence, but they are not a substitute for external review or full device acceptance.

Outstanding release gates include an independent security audit, sharing between two actual Apple Accounts, recovery on separate physical hardware, and signed iOS/AutoFill acceptance on physical devices. Simulator builds do not verify Secure Enclave behavior.

Keep your existing password manager and a verified recovery route while evaluating the project. The [v7 validation record](vault-validation.html) documents completed checks, measurements, and remaining live acceptance work as of September 27, 2026.
