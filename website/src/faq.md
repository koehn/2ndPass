---
layout: guide.njk
permalink: faq.html
title: Our story & FAQ
description: "Why 2ndPass exists, its relationship to the 1Password CLI, and answers about platforms, pricing, and privacy."
eyebrow: A second pass at passwords
heading: "A small tool. A deliberate choice."
intro: "Built because leaving a password manager shouldn’t mean giving up the workflows you rely on."
toc:
  - {id: genesis, label: Why it exists}
  - {id: name, label: The name}
  - {id: different, label: What’s different}
  - {id: op, label: Replacing op}
  - {id: source-access, label: Source access & pricing}
  - {id: platforms, label: Platforms}
  - {id: account, label: Accounts & privacy}
  - {id: ready, label: Is it ready?}
---
## Genesis

### Why did you build 2ndPass?

*From the creator:*

I built 2ndPass because I wanted to stop using 1Password. Its funding of Omacom, the foundation behind Omarchy, was the turning point. I regard the right-wing rhetoric of its leader, David Heinemeier Hansson, as extremist, and I didn’t want my subscription supporting that project.

Leaving the app was only half the problem. I relied on `op`, the 1Password command-line tool, to get secrets into scripts and development tools. I needed a replacement. So I built one—and a native Apple app to go with it.

The result is 2ndPass: passwords and developer secrets, protected with device-bound keys and synchronized through iCloud, with source you can inspect.

### What happened?

The [August 31, 2026 funding announcement](https://omarchy.org/news/2026/08/1password-and-37signals-become-distinguished-corporate-patrons/) says 1Password committed $100,000 annually for three years to Omacom. [Reporting on the controversy](https://allaboutcookies.org/1password-linux-donation-controversy) describes customer objections to Hansson’s political statements and reports 1Password’s response that the donation supported the foundation and was not an endorsement of an individual’s views.

The decision to leave, and the characterization above, are the creator’s own judgment. The linked sources provide the underlying announcement and reporting. 2ndPass is an independent project, with no affiliation to 1Password, Omacom, or Apple.

## Name

### Is it 2ndPass or Second Pass?

Write **2ndPass**, say “Second Pass.” It’s a second pass at the tools used to protect and work with secrets. The website is **2ndpass.app** and the command is `sp`.

Secret references use `sp://`, spelled out because a URI scheme cannot start with a number. Older `mop://` references continue to work. Internal Apple identifiers retain their original names to preserve access to existing keys and vaults.

## Different

### What makes it different?

2ndPass joins two daily workflows: filling a password in an app, and supplying a credential to a command. Native Apple apps and AutoFill handle the first; references, environment injection, and configuration templates handle the second.

Passkeys are implemented in both cloud and local vaults. Cloud passkeys sync across enrolled devices; local passkeys, SSH keys, Git signing keys, and certificate identities keep their private keys in one device’s Secure Enclave. Choosing where keys live is part of the product: local keys cannot be exported or recovered, so register an independent credential on another device. See [vault capabilities](docs.html#vault-capabilities).

Each device has its own Secure Enclave private key. iCloud carries encrypted vault data using your Apple Account, without a separate 2ndPass-hosted vault service. Those choices come with real tradeoffs: Apple-only platforms, an Apple platform and provisioned private-container trust boundary during device enrollment, and portable backups with separately stored keys. Read the [security explanation](security.html) before deciding whether they fit your needs.

## Op

### Can I replace `op` with `sp`?

For supported workflows, yes: read a secret, launch a process with resolved environment variables, or populate a configuration template. Restore a portable archive and update your references and commands using the [migration guide](docs.html#from-op).

It is not a drop-in implementation of every `op` command. There is no automatic lookup in a 1Password account. Check each integration rather than creating a blanket shell alias.

## Source access

### Is the source available? What does it cost?

The source is published for inspection and security review. You may view and analyze it. Copyright © 2026 Koehn Consulting, Inc. All rights reserved.

No license is granted to compile, execute, modify, copy, redistribute, sublicense, sell, or create derivative works from this source code. See the [copyright notice](https://github.com/koehn/2ndPass/blob/main/LICENSE). For licensing inquiries, contact Koehn Consulting, Inc.

Build and installation documentation is for the copyright holder and separately authorized users. Distribution and pricing plans have not been finalized.

## Platforms

### What does it run on? What is missing?

The project targets macOS 15+ and iOS/iPadOS 18+ with supported Secure Enclave hardware. The command-line tool runs on Mac. There is no Windows, Linux, Android, or browser vault client.

Passwords, TOTP, typed items, encrypted attachments, local offline saves, portable archives and developer integrations use the item service. Same-account connection is automatic. General document import, sharing, device removal, account recovery and credential-account management are unavailable. Cloud-key workflows require further physical acceptance. AutoFill can save new logins on iOS/iPadOS 26.2 and later; cards/identities and in-extension password generation are not implemented. See [capabilities](docs.html#vault-capabilities).

## Account

### Do I need another account? Can you see my vault?

There is no separate 2ndPass service account. Synchronization uses your Apple Account and CloudKit. The project does not operate a vault server that receives your secrets.

That does not make iCloud irrelevant to security: Apple account/device security and provisioned, entitlement-protected container access are trusted during own-device enrollment before an owner grants cryptographic membership, and cloud metadata is not all concealed. Read the [iCloud trust boundary](security.html#icloud).

We do not collect personal data through the website or app. This website uses no analytics, cookies, or third-party scripts. Read the [privacy page](privacy.html) for details, including Apple services, hosting-provider logs, and data you choose to send elsewhere.

### Can I use it offline?

Previously stored data can be read and edited offline. Encrypted local saves survive restarts and queue cloud delivery. An offline device cannot know about later changes or revoked access. Attachments need to have been downloaded before going offline.

## Ready

### Should I move everything today?

2ndPass is a development preview. An independent security audit and several physical-device acceptance checks are still outstanding. Evaluate it alongside your current password manager, verify restored records, and keep portable backups with their separate keys before depending on it.


## Offline recovery after device loss

Account-wide live-vault recovery is unavailable. Restore a portable archive with its separate generated key into a new vault, or connect through an existing unlocked device on the same Apple Account. Device-local keys cannot be restored. See [backups](docs.html#recovery).
