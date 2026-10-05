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
  - {id: architecture, label: Devices & vaults diagram}
  - {id: attacks, label: Common attacks}
  - {id: icloud, label: iCloud & account trust}
  - {id: devices, label: Devices & sharing}
  - {id: recovery, label: Recovery}
  - {id: local, label: Local exposure}
  - {id: practices, label: Good habits}
  - {id: status, label: Validation status}
---
## Encryption

Each enrolled device creates separate P-256 private keys for decryption and signing in its Secure Enclave. Those independently generated, hardware-bound device identity keys are non-exportable: the app holds opaque references and asks the Secure Enclave to perform operations without exposing private key material to normal application memory. Each item has its own symmetric key for its separately encrypted fields; each item’s encrypted catalog protects its organization and metadata. A separate device-encrypted display catalog makes local lists efficient.

2ndPass uses authenticated encryption and HPKE (`P256_SHA256_AES_GCM_256`) to wrap secret keys for authorized devices. Independently signed item revisions and pinned membership history help clients detect tampering and known older versions relative to the state they already trust. Vault contents are encrypted locally before they leave the device.

**Secure Enclave protection is not a promise that plaintext never enters memory.** Derived key material and decrypted secrets are used in the app’s process. A compromised, unlocked device or malicious software with sufficient privileges can invoke authorized key operations and capture their plaintext results even when the device private key remains non-exportable. The enclave protects the device’s private key, not everything an application does with a password. Private keys for local-vault identities are generated and used inside the Secure Enclave; metadata and opaque key references are stored outside it. Their private key material cannot be extracted; because of that, these items cannot be synced across devices or backed up.

Apple Passwords/iCloud Keychain also uses substantial Secure Enclave-backed protection; see Apple's [Keychain security documentation](https://support.apple.com/guide/security/secb0694df1a/web). 2ndPass's distinction is its explicit, inspectable device-identity and item-key protocol, not exclusive use of Apple security hardware or a claim of greater security. Apple's system is integrated deeper into the OS and its complete implementation is not publicly inspectable.

The [security design](https://github.com/koehn/2ndPass/blob/main/docs/SECURITY.md) and [vault protocol](vault.html) describe the algorithms, checks, and trust model in detail.

## Architecture

Cloud-access device keys and local credential keys have different jobs. Both are generated in the Secure Enclave, but local keys serve passkey, SSH, Git signing, and certificate operations directly. Cloud device keys open the encrypted keys needed to read a cloud vault and sign item updates and membership changes.

### Devices and local identities

<figure class="security-architecture" tabindex="0" aria-label="Security diagram; scroll horizontally on narrow screens"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 520" role="img" aria-labelledby="architecture-title architecture-description">
<title id="architecture-title">Devices, Secure Enclaves, local vaults, and a cloud vault</title>
<desc id="architecture-description">Two devices independently access one encrypted cloud vault. Each device has its own Secure Enclave keys, encrypted local store and local identities. The cloud holds signed membership history and independently signed item envelopes containing encrypted catalogs, fields, attachments and recipient key wrappers. Local credential keys never sync.</desc>
<defs><marker id="architecture-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#353d87"/></marker></defs><rect x="15" y="10" width="450" height="335" rx="10" fill="#f9f9fc" stroke="#9197bd"/>
<text x="240.0" y="37" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Device A</text>
<rect x="30" y="55" width="420" height="65" rx="10" fill="#ffffff" stroke="#9197bd"/>
<text x="240.0" y="82" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Authorized client + encrypted local store</text>
<text x="240.0" y="105" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Plaintext and temporary keys during use</text>
<path d="M240 120 L240 151" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#architecture-arrow)"/>
<rect x="30" y="155" width="420" height="95" rx="10" fill="#eeeef8" stroke="#9197bd"/>
<text x="240.0" y="182" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Secure Enclave — non-exportable private keys</text>
<text x="240.0" y="205" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Device identity: agreement + signing</text>
<text x="240.0" y="228" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Separate local keys: passkeys, SSH, Git, certificates</text>
<rect x="30" y="270" width="420" height="60" rx="10" fill="#ffffff" stroke="#9197bd"/>
<text x="240.0" y="297" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">local vault: metadata + Keychain references</text>
<text x="240.0" y="320" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Local credential keys never sync or recover</text>
<path d="M240 270 L240 252" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#architecture-arrow)"/>
<rect x="495" y="10" width="450" height="335" rx="10" fill="#f9f9fc" stroke="#9197bd"/>
<text x="720.0" y="37" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Device B — independent keys</text>
<rect x="510" y="55" width="420" height="65" rx="10" fill="#ffffff" stroke="#9197bd"/>
<text x="720.0" y="82" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Authorized client + encrypted local store</text>
<text x="720.0" y="105" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Plaintext and temporary keys during use</text>
<path d="M720 120 L720 151" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#architecture-arrow)"/>
<rect x="510" y="155" width="420" height="95" rx="10" fill="#eeeef8" stroke="#9197bd"/>
<text x="720.0" y="182" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Secure Enclave — non-exportable private keys</text>
<text x="720.0" y="205" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Device identity: agreement + signing</text>
<text x="720.0" y="228" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Separate local keys: passkeys, SSH, Git, certificates</text>
<rect x="510" y="270" width="420" height="60" rx="10" fill="#ffffff" stroke="#9197bd"/>
<text x="720.0" y="297" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">local vault: metadata + Keychain references</text>
<text x="720.0" y="320" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Local credential keys never sync or recover</text>
<path d="M720 270 L720 252" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#architecture-arrow)"/>
<path d="M235 345 L235 422" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#architecture-arrow)"/>
<text x="247.0" y="383.5" fill="#353d87" font-family="system-ui, sans-serif" font-size="15">Cloud sync</text>
<path d="M715 345 L715 422" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#architecture-arrow)"/>
<text x="727.0" y="383.5" fill="#353d87" font-family="system-ui, sans-serif" font-size="15">Cloud sync</text>
<rect x="15" y="425" width="930" height="80" rx="10" fill="#eeeef8" stroke="#9197bd"/><text x="480" y="454" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="18" font-weight="650">Same-account cloud vault in iCloud / CloudKit</text><text x="480" y="482" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Signed membership history + independently encrypted and signed item envelopes</text></svg><figcaption>Each device has independent hardware keys. Cloud credentials can sync; local passkeys, SSH/Git keys, and certificate private keys stay in their original Secure Enclave.</figcaption></figure>

### Inside a cloud vault

<figure class="security-architecture" tabindex="0" aria-label="Security diagram; scroll horizontally on narrow screens"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 335 960 715" role="img" aria-labelledby="vault-structure-title vault-structure-description">
<title id="vault-structure-title">Inside a cloud vault: signed items and membership authority</title>
<desc id="vault-structure-description">A device agreement key opens its recipient wrapper for an item key. Each signed item envelope contains an encrypted item catalog, fields and attachment records. The same item key protects these components. Separately pinned signed membership history authorizes recipients and writers. A device-local display catalog is derived from verified item data and is not uploaded.</desc>
<defs><marker id="vault-structure-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#353d87"/></marker></defs><rect x="40" y="350" width="550" height="64" rx="10" fill="#eeeef8" stroke="#9197bd"/><text x="315" y="377" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Device Secure Enclave agreement key</text><text x="315" y="400" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Opens this device’s envelopes in an authorized client</text><rect x="15" y="450" width="930" height="590" rx="10" fill="#f9f9fc" stroke="#9197bd"/>
<text x="480.0" y="475" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">iCloud / CloudKit — one cloud vault</text>
<rect x="40" y="960" width="880" height="62" rx="10" fill="#eeeef8" stroke="#9197bd"/>
<text x="480.0" y="987" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Separately pinned, signed membership history</text>
<text x="480.0" y="1010" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Authorizes recipients and writers; each signed item binds the exact authority state</text>
<rect x="40" y="490" width="880" height="82" rx="10" fill="#eeeef8" stroke="#9197bd"/>
<text x="480" y="517" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Per-item HPKE wrappers for authorized devices</text>
<text x="480" y="540" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">One item key for its catalog, fields, history and attachments</text>
<text x="480" y="563" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Opened using the recipient device’s agreement key</text>
<path d="M315 414 L315 488" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#vault-structure-arrow)"/>
<path d="M195 572 L195 705" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#vault-structure-arrow)"/>
<path d="M650 572 L650 705" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#vault-structure-arrow)"/>
<rect x="40" y="710" width="310" height="85" rx="10" fill="#eeeef8" stroke="#9197bd"/>
<text x="195.0" y="737" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Encrypted item catalog</text>
<text x="195.0" y="760" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Item names, types, metadata,</text>
<text x="195.0" y="783" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">and field references</text>
<rect x="380" y="710" width="540" height="85" rx="10" fill="#eeeef8" stroke="#9197bd"/>
<text x="650.0" y="737" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Encrypted item fields</text>
<text x="650.0" y="760" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Passwords, notes, cloud passkey / SSH / Git private keys</text>
<text x="650.0" y="783" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Each item has its own symmetric encryption key</text>
<rect x="380" y="860" width="540" height="85" rx="10" fill="#eeeef8" stroke="#9197bd"/>
<text x="650.0" y="887" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16" font-weight="650">Encrypted attachment records</text>
<text x="650.0" y="910" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Encrypted with the owning item key</text>
<text x="650.0" y="933" text-anchor="middle" fill="#20233d" font-family="system-ui, sans-serif" font-size="16">Travel inside the signed item envelope</text>
<path d="M650 795 L650 855" fill="none" stroke="#353d87" stroke-width="2" marker-end="url(#vault-structure-arrow)"/>
<text x="662.0" y="825.0" fill="#353d87" font-family="system-ui, sans-serif" font-size="15">Same item key</text>
<text x="55" y="894" fill="#353d87" font-family="system-ui, sans-serif" font-size="16">Encryption happens on devices.</text>
<text x="55" y="920" fill="#353d87" font-family="system-ui, sans-serif" font-size="16">CloudKit stores ciphertext.</text>
</svg><figcaption>Each independently signed item contains encrypted data and recipient key wrappers. Encryption and decryption happen on authorized devices. Membership history is verified separately; it does not prove that every remote item has been delivered.</figcaption></figure>

Each item has its own key for its encrypted catalog, fields, retained history and attachments. Attachment ciphertext travels with the item envelope; independent attachment transfer is not implemented. Cloud passkeys and SSH/Git keys are encrypted software keys within item payloads. Authorized enrolled devices can use the same cloud credential; local credential private keys cannot move between devices.

**Device identity and local credential private keys stay in the Secure Enclave; decrypted cloud data does not.** The `local` vault holds public metadata and device-only Keychain references, not exported private keys. Authorized clients use decrypted catalogs, item keys, secrets and attachments in process memory.

### Local saves and cloud delivery

The app, CLI and AutoFill share an encrypted Core Data store on each device. An item change and its pending upload commit in the same local transaction. One process owns synchronization for an account/database at a time, using CKSyncEngine to transfer independently signed records. Other clients use the shared store and request synchronization without starting competing long-lived engines.

A successful app save means the edit is durable on this device, including while offline. It does not mean another device has received it. CLI writes normally wait up to 20 seconds for their exact cloud receipts; `--local-save` returns after local commit. A delivery timeout leaves the edit queued and reports pending receipts. Do not repeat a write simply because cloud confirmation timed out. Background scheduling and notifications do not guarantee immediate delivery.

### What the display catalog contains

Local lists use independently encrypted display rows under a device-wrapped catalog key. These rows contain visible metadata and search content, including notes, but exclude passwords, OTP seeds, attachment contents and private-key contents. Rows are bound to their source item versions; stale or damaged derived rows are rebuilt. The display catalog is not uploaded or included in portable archives.

Unlocking can keep that catalog key and visible metadata in the authorized session. Exact secret reads, edits and exports still verify authoritative item state. Lock clears the session key and plaintext views. A partial list is never proof of complete vault inventory. See the [vault architecture](vault.html) for the format and trust checks.

## Attacks

### Stolen files, backups, or cloud data

Vault contents are encrypted before storage or upload. Item keys are wrapped for authorized devices, whose private keys stay in the Secure Enclave. The app stores device-bound key representations in the non-synchronizing Keychain and requires local authentication to use them. A copied encrypted vault does not provide a master-password hash to crack or a portable private key. Copying local storage or the opaque Keychain representation cannot reconstruct the device private key on another machine. This does not protect plaintext exports or an archive stolen together with its separate archive key. Record identifiers, sizes, timing and public membership information are also visible outside content encryption; vault names are encrypted.

### Reading application memory

2ndPass decrypts concealed fields when needed, rather than keeping every password decrypted. Its unlocked display session holds visible catalog data and the display-catalog key, not a persistent collection of revealed passwords or item keys. It wipes owned secret buffers when released and clears session state and hardware-key handles on lock. Passwords and temporary decryption keys still enter memory during use: malware controlling the app or operating system can capture them, and not every copy made by the UI or system frameworks can be reliably erased.

### Modified binaries and injected code

Apple code signing, provisioning, and Keychain access groups protect access to the device identity. On macOS, 2ndPass also checks its signing identity and requires hardened-runtime protections with debugger access and library-validation bypasses disabled. Simply modifying or re-signing the app does not grant an attacker the legitimate app's Keychain access. These protections rely on the operating system; they do not make malicious code with an accepted signing identity safe, and enrollment does not remotely verify which binary another device runs.

### Tampered or replayed cloud records

Authenticated encryption detects altered ciphertext. Each signed item binds its identity, revision and exact membership authority. Clients check the author against independently pinned membership history, reject known older revisions and detect equal-revision forks. An authorized writer can still create new content at a higher revision.

These checks do not provide a global proof of inventory completeness or freshness. A server can withhold newer items, omit records or deny service. Restoring an older entire local store can remove evidence of previously observed changes. Conflicting versions are preserved and block affected publication; complete conflict-review integration and physical concurrent-edit acceptance remain release work.

Without a global publication fence, a stale writer can submit ciphertext encrypted under older keys. Rejecting that record later cannot retract the disclosure. Account takeover is a separate enrollment threat, described below.

### Clipboard and screen capture

Passwords are concealed until requested, revealed values hide again after a timeout, and secret clipboard copies stay local to the device and expire. Locking hides vault contents and clears the app's unchanged clipboard copy. These measures limit exposure, but cannot erase a password another application or screen capture has already obtained.

## iCloud

CloudKit provides transport and storage through your Apple Account. There is no separate 2ndPass-hosted vault service. Secret contents are encrypted by 2ndPass before upload; iCloud carries the ciphertext and encrypted key material.

Apple protects account sign-in with [two-factor authentication](https://support.apple.com/en-us/102660), enabled by default for most accounts: a new device requires the account password and verification through a trusted device or phone number. Optional [Security Keys for Apple Account](https://support.apple.com/en-us/102637) add protection against phishing. 2ndPass uses the system's authenticated iCloud session and never asks for your Apple Account password or verification code. These account security keys are separate from a 2ndPass portable archive key.

**Apple and 2ndPass provide different layers of the trust model.** Apple authenticates the iCloud environment; code signing, provisioning and CloudKit entitlements restrict native client access to the 2ndPass container and its private per-user database. A new device creates its own Secure Enclave identity, submits a signed request through that namespace, and receives item-key envelopes only after an enrolled owner device publishes a signed membership grant. See Apple's [container access](https://developer.apple.com/documentation/cloudkit/ckcontainer) and [private database](https://developer.apple.com/documentation/cloudkit/ckcontainer/privateclouddatabase) documentation.

Ordinary same-account enrollment deliberately reuses Apple's account/device authentication and authorized app access without adding another comparison ceremony. It does not directly query or join Apple's private iCloud Keychain trust circle. Platform sandboxing also contributes on iOS/iPadOS. The Mac app and AutoFill extension enable App Sandbox; the app permits outbound network connections and user-selected file access. The separately installed Mac CLI remains unsandboxed for developer workflows. The Mac packages also use the hardened runtime and restricted entitlements.

**Residual enrollment threat:** an attacker with enough control of your Apple environment to operate an authorized 2ndPass client and access your private 2ndPass container may submit a valid request. If an enrolled owner session processes the exchange while unlocked and online, that identity may receive owner membership and access to existing secrets. Apple Account credentials alone do not permit arbitrary writes into this container. The authenticated private database is an explicit initial trust channel. A joining device verifies its exact scoped request, signed membership history and metadata decryption before installing device-only trust. Discovery alone cannot install authority or replace an existing pin. These checks do not make initial admission independent of that trusted account/container channel.

Encryption does not conceal all metadata. Cloud records expose identifiers, public membership identities, record sizes and timing. Vault names and item contents are encrypted. The local AutoFill index and Apple’s suggestion system receive website, username, and opaque identifier metadata. Passwords and OTP seeds are not placed in that index.

Offline reads use locally stored encrypted items and device-only account bindings. Local item edits also work offline and queue delivery. Offline clients cannot establish current server freshness or observe remote account changes; observed account changes invalidate their local binding. The `--offline` option prevents network use.

## Devices

Each authorized device has its own hardware identity. Other devices on the same Apple Account discover private vaults and connect automatically while an existing device is unlocked. There is no required human comparison code or approval screen. Keep the existing device available until key access and initial item downloading finish.

Admission signs an additive membership successor and wraps item keys for the new device. It preserves concealed-field ciphertext while updating recipient wrappers. Durable staging makes interrupted admission resumable; the joining device verifies metadata before opening. Initial download progress uses a signed record-count hint, not a cryptographic guarantee of complete remote inventory.

Cross-account sharing, device removal and permanent vault deletion are currently unavailable. Their presence in a design or a test fixture must not be mistaken for a usable release feature. Future revocation must address membership and per-item keys, but no revocation mechanism can erase plaintext, retained keys or historical ciphertext that a recipient already copied. If someone knows a service password, change it at the service when their access must end.

Device-local credentials remain a separate choice: their private keys never leave the original Secure Enclave. Register an independent credential on another device rather than assuming that a cloud vault or portable archive can recover them.

## Recovery

Portable backups provide an independent restore path for transferable vault contents. Export creates an encrypted `.moparchive` and a separately generated key. Both are required to restore into a new owned vault without the original device keys or cloud zone. Anyone who obtains both can decrypt the archive, so store them separately.

Archives preserve locally available item fields, metadata, retained history, trash, attachment bytes and cloud software credential bytes. They do not export Secure Enclave private keys or reinstate sharing, device membership or account recovery configuration. Restoring a credential’s bytes does not prove it remains registered or accepted by its website or server.

The current exporter cannot certify complete remote inventory. Finish downloading, inspect the source and verify restored contents before relying on a backup or discarding the original. Use a fresh restore UUID and retain it for retries. The [backup guide](docs.html#recovery) provides commands, and the [standalone archive specification](https://github.com/koehn/2ndPass/blob/main/docs/formats/PORTABLE-BACKUP-v1.md) documents the format independently of an installed app.

Account-wide recovery of a live cloud vault is unavailable. If another enrolled device remains accessible, keep it unlocked while a new device connects through the same Apple Account. A portable archive cannot restore Apple Account access, and neither synchronization nor backup can recover device-local hardware keys.

## Local

The app conceals sensitive fields and uses authentication to unlock access. AutoFill uses a fresh authentication session for each fill. These controls reduce accidental exposure; they cannot make a compromised operating system safe.

The CLI deliberately releases plaintext where you ask it to:

- `read` writes a plaintext secret to standard output or the requested file.
- `run` gives resolved secrets to a child process through its environment. Default output masking matches exact secret bytes; transformed output, files, and network traffic are outside that protection.
- `inject` writes literal plaintext values to stdout or generated configuration files. It does not escape values for the destination format.
- Attachment exports contain plaintext. External password-manager export files also contain plaintext; general document import is not currently connected to the vault service.

The child process, its dependencies and descendants receiving the environment become trusted with the secret. Environment variables can leak through the program itself, diagnostics or privileged host access; they are not a secure container. 2ndPass cannot control what an arbitrary child does with plaintext. This disclosure is necessary for developer-secret automation.

AutoFill shares the app's provisioned Keychain group and device identity, but requires its own fresh authentication. Its extension and the receiving app/site are also within the plaintext trust boundary.

Treat those outputs as credentials. Removing a temporary file is ordinary deletion, not a guarantee of secure erasure. Shell history, logs, screen sharing, backups, and a child process can all create additional copies.

## Practices

1. Protect your Apple Account, its recovery channels, and trusted devices. Review unfamiliar devices promptly.
2. Keep macOS/iOS and 2ndPass current. Lock your device and the app when you step away.
3. Use distinct, generated passwords. Enable service-level multi-factor authentication where available.
4. Keep references in project files and actual secrets out of source control. Review programs before handing them credentials.
5. Verify portable restores before discarding source data. Remove unwanted plaintext exports and check where they may have been backed up.
6. Keep portable archives and their generated keys separately. Test restoration and register independent credentials for device-local keys.
7. Treat automatic same-account connection as part of your Apple Account trust boundary. Rotate credentials at their services when copied passwords or keys must stop working.

## Status

**2ndPass is a development preview, not an independently audited release.** Automated tests and hardware checks are useful evidence, but they do not substitute for external review or full device acceptance.

The maintainer reported successful same-account enrollment on October 3, 2026. On October 4, an item created on iPhone reached Mac and iPad, an edit on Mac reached both other devices, and an offline iPhone edit uploaded after reconnection without manual Refresh. These are physical-device observations for those scenarios, not proof of all synchronization behavior.

Remaining gates include concurrent-edit conflict resolution, interruption and account-change handling, signed app/CLI/AutoFill acceptance across supported platforms, complete backup-inventory verification, Production provisioning and independent security review. Sharing, device removal and account recovery require implementation before their own physical acceptance. Simulator builds do not verify Secure Enclave behavior or real cross-account permissions.

Keep your existing password manager and verified portable backups while evaluating the project. The [validation record](vault-validation.html) distinguishes completed observations from outstanding work, and the [security design](https://github.com/koehn/2ndPass/blob/main/docs/SECURITY.md) describes the current technical boundaries.
