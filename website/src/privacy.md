---
layout: guide.njk
permalink: privacy.html
title: Privacy
description: "2ndPass does not collect personal data through its website or app. Learn what stays on your devices and what Apple handles for synchronization."
eyebrow: Privacy
heading: "Your data isn't our business."
intro: "We don't collect personal data about you through the 2ndPass website or app. No analytics, advertising, or tracking."
toc:
  - {id: website, label: The website}
  - {id: app, label: The app}
  - {id: apple, label: Apple services}
  - {id: choices, label: Data you choose to send}
---
## Website

The 2ndPass website does not collect personal information, track visitors, or
build user profiles. It uses no analytics, cookies, advertising trackers, or
third-party scripts. Images, styles and scripts are served with the site; its
JavaScript only adds copy buttons to code examples.

Serving a page necessarily involves the hosting provider handling your request,
including your IP address. The provider may process ordinary access logs. Our
no-collection policy is not a claim that visiting a website creates no network
records. Following an external link takes you to a service with its own privacy
practices.

## App

The 2ndPass app, AutoFill extension and CLI do not send personal data, vault
contents, usage analytics or tracking identifiers to us. There is no separate
2ndPass account or developer-operated vault server. We do not sell your data or
use it for advertising.

The app processes your data to provide the features you use. It stores encrypted
vault data, device-bound key references and preferences on your devices. The
Recently Used feature records item identifiers and access times locally; those
usage records are not sent to us or synchronized through iCloud. Local operating
system diagnostic logs are not an app analytics feed to us.

This distinction matters: **we do not collect your data, but the app must handle
it to work.** Passwords and temporary decryption keys enter app memory when used.
See the [security page](security.html) for encryption and endpoint protections.

## Apple

Synchronization uses your Apple Account and Apple's CloudKit service. Vault
contents are encrypted by 2ndPass before upload. Apple handles the storage and
transport; some metadata, including vault names, public device identities,
ciphertext sizes and timing, is not concealed from that service. The Developer
setting also synchronizes through Apple's iCloud key-value storage.

When you enable AutoFill, 2ndPass supplies Apple's credential suggestion system
with website, username and credential-locator metadata. That index does not
contain passwords or OTP seeds. Filling a credential intentionally delivers it
to the destination app or website.

Apple's services and any system-level diagnostics are governed by your Apple
settings and Apple's privacy practices. They are separate from data collection
by 2ndPass's developers.

## Choices

Copying a password, exporting a file, or using CLI commands deliberately sends
data to the destination you select. `read` and `inject` can produce plaintext
output; `run` gives secrets to a child process. That destination controls what
happens to the data afterward.

If you voluntarily submit an issue or contact the project, we receive what you
choose to share. GitHub issues are public. Do not include passwords, tokens,
vault backups or other private information in a report.

Last updated September 29, 2026.
