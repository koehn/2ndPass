---
layout: guide.njk
permalink: docs.html
title: Documentation
description: "Install 2ndPass, use AutoFill, edit offline, run commands with secrets, and make portable backups."
eyebrow: The field guide
heading: "Make it part of your day."
intro: "From your first vault to your next deploy. Practical guides for the app and the command line."
toc:
  - {id: start, label: Start here}
  - {id: first-vault, label: Your first vault}
  - {id: vault-capabilities, label: Vault capabilities}
  - {id: cli, label: The sp CLI}
  - {id: key-credentials, label: Passkeys, SSH & Git}
  - {id: import, label: Import passwords}
  - {id: items, label: Organize & generate}
  - {id: autofill, label: Passwords & AutoFill}
  - {id: references, label: Secret references}
  - {id: runtime, label: Run with secrets}
  - {id: templates, label: Configuration templates}
  - {id: from-op, label: Moving from op}
  - {id: attachments, label: Attachments}
  - {id: sharing, label: Devices & sharing}
  - {id: recovery, label: Encrypted backups}
  - {id: offline-recovery-after-device-loss, label: Recovery keys}
  - {id: troubleshooting, label: Troubleshooting}
---
## Start

The source is published for inspection and security review only. The build, installation, and usage instructions below are for the copyright holder and separately authorized users. Contact Koehn Consulting, Inc. for licensing; see the [copyright notice](https://github.com/koehn/2ndPass/blob/main/LICENSE).

**2ndPass is a development preview.** It requires macOS 15+ or iOS/iPadOS 18+, supported Secure Enclave hardware, and an Apple Account with iCloud access. Read the [security and validation notes](security.html#status) before entrusting it with your primary credentials. Keep your current password manager available while evaluating it.

### Build and install on a Mac

Use a Mac with Xcode and its command-line tools. Clone the [source repository](https://github.com/koehn/2ndPass), then configure Apple signing. Operational vault access requires a signed, provisioned app; a bare `swift build` is useful for compilation and CLI help, but cannot open your secrets.

1. Configure separate app, AutoFill extension, and CLI App IDs with their documented CloudKit, App Group, and Keychain capabilities under your Apple developer team.
2. Download a provisioning profile for each target. The CLI uses its own `.CLI` App ID and profile.
3. Configure the CloudKit schema and choose the matching Development or Production environment.
4. Package and install from the repository root:

```sh
export MOP_SIGN_IDENTITY='Your Apple signing identity'
export MOP_PROVISION_PROFILE='/path/to/app.provisionprofile'
export MOP_AUTOFILL_PROVISION_PROFILE='/path/to/autofill.provisionprofile'
export MOP_CLI_PROVISION_PROFILE='/path/to/cli.provisionprofile'
export MOP_CLOUD_ENVIRONMENT='Development'
just cli-install
just app-install
open /Applications/2ndPass.app
sp --help
```

The sandboxed GUI installs at `/Applications/2ndPass.app` and contains no CLI. The separate CLI installer places its signed bundle under `/usr/local/lib/sp` and links `/usr/local/bin/sp`, manpages, and shell completions. Keep the CLI inside its own signed bundle. Install it before upgrading an older combined app. The CLI remains unsandboxed so it can launch developer tools and serve SSH/Git clients. See [CLI provisioning and distribution](https://github.com/koehn/2ndPass/blob/main/docs/HOMEBREW.md). `MOP_*` settings and internal identifiers retain their old names for compatibility; see the [branding notes](https://github.com/koehn/2ndPass/blob/main/docs/BRANDING.md).

The [build README](https://github.com/koehn/2ndPass#build-and-provision), [CloudKit setup](https://github.com/koehn/2ndPass/blob/main/docs/CLOUDKIT.md), and [iPhone/iPad build guide](https://github.com/koehn/2ndPass/blob/main/docs/MOBILE.md) contain the full provisioning requirements. `just ios-build` checks the simulator and device builds; `just ios-archive` creates a signed archive when signing is configured.

## First vault

Create a vault in the signed app, or use `sp vault init personal`. Existing private vaults on the same Apple Account connect automatically. Keep an existing device unlocked until key access arrives; items then download in the background. Restoring a portable archive creates an independent vault, not a second-device connection.

Read the [vault architecture](vault.html) and [validation status](vault-validation.html).

## Vault capabilities

| Capability | Cloud vault | Device-local vault |
| --- | --- | --- |
| Passwords, notes, TOTP and typed fields | Encrypted item records | Not a general secrets store |
| Same-account synchronization | Yes; local saves queue delivery | No |
| Offline item edits | Yes | Local hardware operations only |
| SSH/Git keys | Software keys, generated or imported | Hardware-generated keys only |
| Passkeys | Software credentials; physical acceptance pending | Device-bound; platform limitations apply |
| Portable backup | Local transferable contents and separate key | Private keys cannot be exported |
| Account recovery, sharing, device removal | Unavailable | No key recovery |

Cloud private keys enter authorized process memory. Local private keys stay in the Secure Enclave. Credential-account management and general document import remain unavailable. See [cloud credentials](https://github.com/koehn/2ndPass/blob/main/docs/CLOUD-KEY-CREDENTIALS.md) and [local identities](https://github.com/koehn/2ndPass/blob/main/docs/LOCAL-VAULT.md).

## CLI

**`sp` is the separately installed Mac command-line tool.** Use the same vaults from Terminal, scripts, and developer tools:

- **Read and write secrets:** use `sp read` and `sp write` with [secret references](#references).
- **Run tools with credentials:** `sp run` resolves references into a child process’s environment for local development, database clients, and API tools. Keep references in project files instead of literal secrets.
- **Build configuration files:** `sp inject` fills [configuration templates](#templates) for tools such as npm.
- **Authenticate and sign:** `sp ssh-agent` serves selected SSH or Git signing keys to a wrapped command or an agent-capable IDE. Cloud and device-local keys are supported.
- **Manage vault data:** manage items and attachments, and export or restore portable archives.

```sh
# Supply a stored token to GitHub CLI.
GH_TOKEN=sp://personal/github/token sp run -- gh repo list --limit 10

# Supply stored credentials to your development server.
sp run --env-file app.env -- npm run dev

# Use an existing selected SSH credential.
sp ssh-agent --vault personal --identity server -- ssh user@example.com
```

Install the CLI using [the Mac setup instructions](#start). Run `sp --help`, `sp COMMAND --help`, or `man sp` for command details. Commands receiving secrets are trusted with plaintext; output masking is not a sandbox. See [runtime behavior](#runtime) and [moving from op](#from-op).

## Key credentials

Create passkeys from a website’s registration flow: select 2ndPass, then explicitly choose a cloud vault or **This Device — Secure Enclave**. Cloud registration and publication need end-to-end physical acceptance; a durable local save alone is not cloud confirmation. Local passkeys are device-bound and may encounter platform compatibility restrictions; they are not backed up.

Choose **New → New SSH Key** to generate or import a key and select its destination and purpose. SSH authentication (including Git fetch/push) and Git commit signing are distinct purposes. For cloud keys, supported imports are single-key OpenSSH files, including bcrypt/AES-256-CTR encrypted files. Legacy PEM/PKCS#1/PKCS#8 files are not supported. Existing SSH text items need an explicit Save to validate and convert their key material.

```sh
sp item create --vault personal --type ssh --name server --algorithm ed25519
sp item create --vault personal --type git-signing --name commits --algorithm p256
sp item import-ssh --vault personal --name imported --purpose ssh ~/.ssh/id_ed25519
sp item public-key --vault personal commits
```

Register the public key with the destination service. For Git signing, register it as a signing key, then configure Git with the actual public key:

```sh
git config gpg.format ssh
git config user.signingkey 'key::ecdsa-sha2-nistp256 PUBLIC_KEY_BASE64'
sp ssh-agent --vault personal --purpose git-signing --identity commits -- git commit -S
```

The app’s credential details provide commands for the actual key and vault. Each agent session serves one vault and selected identities. With no wrapped command, the agent runs in the foreground and prints a socket path for `SSH_AUTH_SOCK`; it does not install a persistent background agent. See the [complete SSH/Git guide](https://github.com/koehn/2ndPass/blob/main/docs/CLOUD-KEY-CREDENTIALS.md#ssh-and-git).

## Import

General CSV, JSON and 1PUX document import is not connected to the current service. Parser support in the source is not a supported import workflow. Keep your source manager available.

You can restore a portable `.moparchive` with its separate generated key; see [backups](#recovery). Restore preserves transferable contents and creates a new owned vault.

## Items

Use the app’s New menu to create logins, notes, API credentials, cards, identities, documents, and other item types. Add typed fields, tags, and favorites to make entries easier to find. Use the password generator in the editor to create a password, adjusting its options before saving.

- **Vaults:** keep separate sets of credentials. Commands that manage a vault require a selection when there is more than one.
- **Archive:** keep an item without showing it in normal lists or AutoFill. Use the Archived filter to find it again.
- **Recently Deleted:** inspect and restore trashed items. Permanent deletion is not currently available.
- **Concealed fields:** passwords, tokens, OTP seeds, and recovery codes are hidden by default.

Save edits before locking. Unsaved drafts are not persisted across a security lock or restart. Usable SSH/Git credentials work with the separately installed `sp ssh-agent`; existing SSH text items require explicit validation and conversion when saved. Cards and identities do not have system AutoFill integration.

## AutoFill

1. Open your device’s system **AutoFill & Passwords** settings and enable **2ndPass** as a provider.
2. Open and unlock 2ndPass. In **Settings → AutoFill**, choose **Refresh Suggestions**.
3. For a Login item, provide a website and username. In **Edit Item → Use for AutoFill**, select the username, password, and optional verification-code fields.
4. Select a suggestion in an app or browser and authenticate to fill it.

2ndPass supports saved passwords, TOTP verification codes, and passkeys. Every fill uses a fresh authentication session. Website and username metadata are supplied to Apple’s credential system for suggestions; passwords and OTP seeds are not included in that index.

For missing suggestions, check the item’s website and field types, then refresh suggestions again. Create passkeys from a website’s registration flow and choose cloud or device-local storage. Saving new logins through AutoFill is supported on iOS/iPadOS 26.2 and later; password generation inside AutoFill is not implemented. See the [AutoFill guide](https://github.com/koehn/2ndPass/blob/main/docs/AUTOFILL.md) for platform details.

## References

A reference points to a field without containing its secret:

```text
sp://vault/item/[section/]field
```

Use percent encoding for spaces and other special characters, for example `sp://personal/My%20Login/password`. Names are case-sensitive. Copying a reference from the app is the easiest way to get the correct spelling. Renaming items or vaults means updating references that use those names.

```sh
# Prompts for a hidden value; do not put the secret in the command line.
sp write sp://personal/github/token

# Replace a value already stored at that reference.
sp write sp://personal/github/token --replace

# Prints the secret: choose where stdout goes carefully.
sp read sp://personal/github/token
```

`mop://` references remain supported. The new scheme is `sp://`, with the word spelled out; URI schemes cannot begin with a number.

## Runtime

Give a child process a secret without putting the literal value in a checked-in environment file:

```sh
GH_TOKEN=sp://personal/github/token \
  sp run -- gh repo list --limit 10
```

For a local application, create a `development` vault and store your credentials first:

```sh
sp vault init development
sp write sp://development/db/user
sp write sp://development/db/password
```

Save a reference-only `app.env`:

```dotenv
APP_ENV=development
PGHOST=localhost
PGUSER=sp://${APP_ENV}/db/user
PGPASSWORD=sp://${APP_ENV}/db/password
```

Then launch your project:

```sh
sp run --env-file app.env -- npm run dev
```

All references must resolve before the command starts. The launched process and its children receive plaintext credentials in their environment; the invoking shell does not receive the resolved values. Later `--env-file` arguments override earlier ones. Variable expansion applies inside references, not arbitrary dotenv strings.

Exact secret occurrences in stdout and stderr are masked by default. This is not a sandbox: encoded or transformed secrets, files, and network output can still leak. Use `--no-masking` when direct terminal behavior is necessary, knowing it disables output filtering.

The child process, its dependencies and inheriting descendants receive plaintext
secrets and become trusted with them. Environment variables may leak through the
program, diagnostics or privileged host access. 2ndPass cannot control arbitrary
child-process file writes, network traffic or transformed output. `read` likewise
releases plaintext to stdout or its requested output file. This is the necessary
boundary of developer-secret automation; see [local exposure](security.html#local).

## Templates

For software that needs a configuration file, write a template containing placeholders:

```ini
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken={{ sp://personal/npm/token }}
```

Store the npm token, then materialize the configuration only for the command:

```sh
sp write sp://personal/npm/token

(
  config_dir=$(mktemp -d "${TMPDIR:-/tmp}/sp-npm.XXXXXXXX") || exit
  trap 'rm -rf "$config_dir"' EXIT
  sp inject --in-file npmrc.template \
    --out-file "$config_dir/npmrc" --file-mode 0600 || exit
  npm --userconfig "$config_dir/npmrc" whoami
)
```

The generated file contains plaintext. The receiving program and anyone able to read its output files are trusted with it; file permissions do not encrypt the contents. Cleanup is ordinary deletion, not secure erasure, and a forced process kill may prevent the trap from running. `inject` inserts values literally; it does not escape JSON, YAML, INI, or URL syntax. Use a serializer for values requiring format-specific escaping.

## From op

The workflow will feel familiar, but **2ndPass is not a drop-in implementation of the 1Password CLI**.

| Existing habit | 2ndPass approach |
| --- | --- |
| `op read` | Store or restore the item, then use `sp read sp://…` |
| `op run` | Update references and use `sp run --env-file FILE -- COMMAND` |
| `op inject` | Use `{{ sp://… }}` placeholders with `sp inject` |
| A 1Password export | Document import integration remains planned |

There is no automatic lookup in 1Password or Apple Passwords. Review flags, field paths, and dotenv behavior for each script. Do not blindly alias `op` to `sp`. See [more integration recipes](https://github.com/koehn/2ndPass/blob/main/docs/EXAMPLES.md) for Docker, GitHub, npm, and SSH.

## Attachments

In the item editor, add an Attachment field and choose a file. The Document template starts with an attachment. Files are encrypted and limited to 8 MiB each. Attachment ciphertext downloads with its item during synchronization, even if you never open the file. Opening or exporting decrypts the locally stored contents after authentication; downloaded attachments work offline. The current app has no attachment download preference.

For an existing item:

```sh
sp item attachment add proof.pdf \
  --vault personal --item "Account" --field proof
sp item attachment export sp://personal/Account/proof \
  --output ./proof.pdf
```

Export creates a plaintext, owner-only file and refuses to overwrite an existing destination. AutoFill does not expose attachment contents. This does not prevent the app from downloading their ciphertext during synchronization.

## Sharing

Devices on the same Apple Account connect automatically while an existing device is unlocked. No access-request approval or comparison code is required. The authenticated private iCloud container is an explicit enrollment trust channel; see [account trust](security.html#icloud).

Cross-account sharing, device removal and permanent vault deletion are unavailable. Removing a stored credential cannot retract secrets already copied or revoke it at the external service.

## Recovery

Export the locally stored inventory with a separate generated key:

```sh
sp vault backup --offline --vault VAULT_UUID /path/vault.moparchive --key-file /separate/path/vault.key
sp vault restore-backup /path/vault.moparchive --key-file /separate/path/vault.key --name restored --restore-id NEW_UUID --dry-run
sp vault restore-backup /path/vault.moparchive --key-file /separate/path/vault.key --name restored --restore-id NEW_UUID
```

Generate a fresh restore UUID and retain it for retries. Keep the archive and key separately; both are needed. Restore creates a new owned vault and does not restore device-local keys or membership. Verify restored contents before discarding the source. Exports cannot currently certify complete remote inventory. See the [backup guide](https://github.com/koehn/2ndPass/blob/main/docs/BACKUPS.md).

## Troubleshooting

- **Signing error:** use the separately installed, signed and provisioned CLI through its installed symlink. An unsigned binary cannot access the vault. Keep identifiers and CloudKit environments consistent.
- **Waiting for another device:** unlock 2ndPass on an enrolled owner device. Locked or suspended apps cannot grant access. Check connectivity and use Retry.
- **Offline:** use `sp read --offline sp://personal/item/password` for previously verified local data. Local saves also work offline and queue cloud delivery. Offline access cannot learn about remote changes or prove freshness.
- **Conflicting edit:** keep the draft, refresh, and resolve the conflict. Do not assume your write overwrote another device’s changes.
- **Pending write:** CLI confirmation normally waits up to 20 seconds. A timeout leaves the local save queued; do not repeat it. Use `sp vault sync --vault personal`. `--local-save` returns after local commit.
- **Need a flag:** use `sp --help`, `sp COMMAND --help`, or `man sp`.

Report reproducible problems in the [repository’s issue tracker](https://github.com/koehn/2ndPass/issues). Never include passwords, tokens, plaintext exports, or sensitive vault contents in a report.

## Offline recovery after device loss

Account-wide recovery of a live cloud vault is unavailable. Prepare a [portable archive and its separate key](#recovery) for independent restoration. If another enrolled device remains available, keep it unlocked while a new device connects on the same Apple Account. Device-local Secure Enclave keys cannot be recovered; register independent credentials on another device.
