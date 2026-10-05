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

Each device has independent Secure Enclave agreement and signing keys. Item keys are wrapped for authorized devices using HPKE, and fields are encrypted before cloud transfer. Plaintext secrets and temporary item keys enter authorized process memory during use. Hardware protection does not protect a compromised unlocked process from its own plaintext.

## Architecture

The app, CLI and AutoFill share an encrypted device-local store. Each item change and pending upload commits atomically. One synchronization owner per account/database transfers records through CKSyncEngine. A device-encrypted display catalog accelerates lists; explicit reads verify authoritative items. See the [vault architecture](vault.html).

## Attacks

Signed items bind per-item revisions and signed membership authority. Clients reject known older revisions and equal-revision forks. These checks do not prove global inventory completeness or cloud freshness. An authorized writer can write new content at a higher revision; omission, deletion and corruption can deny service.

## iCloud

Same-account enrollment explicitly trusts the authenticated private CloudKit container for bootstrap. An existing unlocked device automatically signs admission and rewraps item keys. The joining device checks its scoped request, signed history and metadata decryption before installing trust. Discovery alone cannot replace an existing trust pin.

An attacker able to write through that account/container channel may gain admission while an existing unlocked device processes the request. There is no additional human comparison step. Protect the Apple Account and authorized devices. Offline clients cannot detect unobserved remote changes.

## Devices

Each client authenticates independently. Other devices on the same Apple Account connect automatically while an existing device is unlocked. Cross-account sharing and device removal are unavailable. Device-local credential keys cannot be synchronized, exported or recovered.

## Recovery

Portable backups use a separately generated archive key. Both archive and key are required for restoration into a new owned vault. Exports reflect local inventory and cannot certify complete remote inventory. Account-wide live-vault recovery is unavailable. See [backup instructions](docs.html#recovery).

## Local

Lock clears protected views and session keys. Passwords still reach clipboard destinations, filled apps and commands receiving them. `read` and `inject` output plaintext; `run` gives plaintext environment values to the child and its descendants. Exact-byte output masking does not control transformed output, files, diagnostics or network traffic.

AutoFill supplies website and username suggestion metadata to Apple's credential system, not passwords or OTP seeds. A selection is resolved after fresh authentication.

## Practices

Protect your Apple Account and devices. Keep archive keys separately from backups and verify restored contents. Register independent credentials for device-local keys. Keep your current password manager available while evaluating this preview.

## Status

The user confirmed same-account enrollment on October 3, 2026 and basic cross-device synchronization plus an offline edit on October 4. Concurrent-edit resolution, account recovery, cross-account permissions, Production readiness and independent security review remain separate gates. See [validation](vault-validation.html) and the [full security model](https://github.com/koehn/2ndPass/blob/main/docs/SECURITY.md).
