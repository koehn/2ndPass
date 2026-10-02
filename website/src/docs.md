---
layout: guide.njk
permalink: docs.html
title: Documentation
description: "Install 2ndPass, import passwords, use AutoFill, run commands with secrets, share vaults, and prepare recovery."
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

For the technical design, read the [vault protocol](vault.html) and its [validation record](vault-validation.html).


The CLI equivalent is:

```sh
sp vault init personal
sp vault list
```

If an existing vault is discovered but this device is not enrolled, the app offers **Connect this device**. Unlock 2ndPass on an existing owner device to let it process the enrollment request. [Learn about this trust boundary](security.html#icloud).


## Vault capabilities

Choose a cloud vault for secrets you need across devices, or the fixed **`local`** vault for identities whose private keys stay in this device’s Secure Enclave.

| Secret or capability | Cloud vault | Device-local `local` vault |
| --- | --- | --- |
| Logins, passwords, API tokens, database credentials, secure notes | Yes | No |
| TOTP seeds and recovery codes | Yes, as concealed fields | No |
| Payment cards, identities, documents, encrypted attachments | Yes | No |
| Passkeys | Synced software P-256 keys | Device-bound Secure Enclave P-256 keys; platform compatibility limits apply |
| SSH authentication and Git SSH signing | Generate Ed25519 or P-256; import Ed25519, P-256, or RSA 2048–8192-bit OpenSSH keys | Generate Secure Enclave P-256 keys only; no private-key import |
| Certificate identities and certificate signing requests (CSR) | No usable certificate workflow; files/text can be stored as ordinary secrets | Generate keys, create CSRs, attach certificates; export public material |
| Sync between devices | Yes, through iCloud | No |
| Offline recovery copy | Covers owned cloud vaults when configured | No backup or recovery |

Cloud credential private keys are encrypted software keys, available to authorized clients during use. Local private keys cannot be exported, synchronized, or moved to a cloud vault. Device loss or erasure permanently loses local identities: register an independent credential on another device first. Passkey import/export is not implemented. Storing key text or a certificate file does not by itself create a usable credential.

Encrypted checkpoint exports are backups of cloud ciphertext, not another selectable vault type. Import requires an already enrolled device and an independently recorded checkpoint digest; it does not restore a missing cloud zone. Offline recovery restores access to owned live cloud vaults, including their cloud credentials, but cannot restore an Apple Account or missing cloud data. Cross-account sharing remains preliminary and is not a supported release feature.

See [cloud credential formats and limitations](https://github.com/koehn/2ndPass/blob/main/docs/CLOUD-KEY-CREDENTIALS.md), [device-local identities](https://github.com/koehn/2ndPass/blob/main/docs/LOCAL-VAULT.md), and [recovery setup](#offline-recovery-after-device-loss). Hardware, live sync, and cross-account acceptance checks remain distinct from automated software tests.

## CLI

**`sp` is the separately installed Mac command-line tool.** Use the same vaults from Terminal, scripts, and developer tools:

- **Read and write secrets:** use `sp read` and `sp write` with [secret references](#references).
- **Run tools with credentials:** `sp run` resolves references into a child process’s environment for local development, database clients, and API tools. Keep references in project files instead of literal secrets.
- **Build configuration files:** `sp inject` fills [configuration templates](#templates) for tools such as npm.
- **Authenticate and sign:** `sp ssh-agent` serves selected SSH or Git signing keys to a wrapped command or an agent-capable IDE. Cloud and device-local keys are supported.
- **Manage vault data:** import supported password-manager exports, manage items and attachments, and configure offline recovery from the terminal.

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

Create passkeys from a website’s registration flow: select 2ndPass, then explicitly choose a cloud vault or **This Device — Secure Enclave**. Cloud registration requires a successful online save. Local passkeys are device-bound and may encounter platform compatibility restrictions; they are not backed up.

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

Choose **Import…** from the Mac File menu or the app’s New menu. Select your export and destination vault, review records and warnings, then import. Existing entries are not overwritten; duplicates and conflicts are reported and skipped.

| Source | Supported input |
| --- | --- |
| 1Password | CSV or 1PUX v3; prefer 1PUX for richer fields and attachments |
| Bitwarden | CSV or unencrypted JSON; prefer JSON for richer items |
| Apple Passwords / Safari | Password CSV; extract the CSV from Safari ZIP exports first |
| Chrome | Password CSV |
| LastPass | Generic password / secure-note CSV |

Preview a batch before importing:

```sh
sp item import export.1pux --vault personal --dry-run
sp item import export.1pux --vault personal --yes
```

Source exports contain **plaintext secrets**. Store them carefully, verify the import, then remove unwanted copies yourself. 2ndPass does not delete the source export. Passkeys and password history are not migrated. Check every warning before closing your old account. See the [complete import guide](https://github.com/koehn/2ndPass/blob/main/docs/IMPORT.md) for supported fields, limits, and attachment handling.

## Items

Use the app’s New menu to create logins, notes, API credentials, cards, identities, documents, and other item types. Add typed fields, tags, and favorites to make entries easier to find. Use the password generator in the editor to create a password, adjusting its options before saving.

- **Vaults:** keep separate sets of credentials. Commands that manage a vault require a selection when there is more than one.
- **Archive:** keep an item without showing it in normal lists or AutoFill. Use the Archived filter to find it again.
- **Recently Deleted:** restore items for 30 days. Expired entries are removed when the app is unlocked and online.
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
| `op read` | Store/import the item, then use `sp read sp://…` |
| `op run` | Update references and use `sp run --env-file FILE -- COMMAND` |
| `op inject` | Use `{{ sp://… }}` placeholders with `sp inject` |
| A 1Password export | Review a 1PUX or CSV import into a selected vault |

There is no automatic lookup in 1Password or Apple Passwords. Review flags, field paths, and dotenv behavior for each script. Do not blindly alias `op` to `sp`. See [more integration recipes](https://github.com/koehn/2ndPass/blob/main/docs/EXAMPLES.md) for Docker, GitHub, npm, and SSH.

## Attachments

In the item editor, add an Attachment field and choose a file. The Document template starts with an attachment. Files are encrypted, limited to 8 MiB each, and downloaded on demand by default. To prefetch, choose **Settings → Advanced → Attachments on this device → During sync**. Already cached encrypted files can be read offline.

For an existing item:

```sh
sp item attachment add proof.pdf \
  --vault personal --item "Account" --field proof
sp item attachment export sp://personal/Account/proof \
  --output ./proof.pdf
```

Export creates a plaintext, owner-only file and refuses to overwrite an existing destination. AutoFill does not download attachment contents.

## Sharing

**Your devices:** open 2ndPass on the new device, select the existing vault, and connect. Keep an enrolled owner device unlocked to process the request. Apple account/device security, signing, provisioning and CloudKit entitlements protect the private per-user namespace used for bootstrap. An owner then grants membership cryptographically. Account credentials alone do not authorize arbitrary enrollment writes; see the [precise enrollment threat](security.html#icloud). No extra human comparison is required for this ordinary flow.

**Another person:** use **Share with another person**. Choose editor or viewer access, exchange the invitation/acceptance files, verify the identity details requested by the app, and complete approval. An iCloud share invitation alone does not grant decryption rights. Both people need compatible clients.

**Removal:** use **Settings → devices** for enrolled personal devices, or the vault’s membership controls for other people. Removal rotates per-item keys and the catalog key and rewrites all retained field ciphertext, including recently deleted items and attachments. It cannot revoke plaintext or old backups already copied by a recipient; change the underlying service password when necessary.

Cross-account vault sharing is not yet implemented as a supported feature; the
controls and commands above describe preliminary code. The
[mailbox design detail](security.html#devices) must be addressed when implementing
sharing, followed by physical two-account validation. It is not a current product
vulnerability. See the [enrollment and sharing commands](https://github.com/koehn/2ndPass#add-devices-and-share).

## Recovery

Set up an [offline recovery copy](#offline-recovery-after-device-loss) to recover access after device loss. It covers owned live cloud vaults, including cloud passkeys and SSH/Git keys; it does not recover device-local identities.

Save an encrypted backup and independently record the trusted checkpoint:

```sh
sp vault export --vault personal personal-backup.json
sp vault fingerprint --vault personal
```


## Troubleshooting

- **Signing error:** use the separately installed, signed and provisioned CLI through its installed symlink. An unsigned binary cannot access the vault. Keep identifiers and CloudKit environments consistent.
- **Waiting for another device:** unlock 2ndPass on an enrolled owner device. Locked or suspended apps cannot grant access. Check connectivity and use Retry.
- **Offline:** use `sp read --offline sp://personal/item/password` for previously verified local data. Offline access is read-only and cannot learn about revocation or prove freshness.
- **Conflicting edit:** keep the draft, refresh, and resolve the conflict. Do not assume your write overwrote another device’s changes.
- **Uncertain write:** use `sp vault sync --vault personal` to reconcile before retrying a mutation.
- **Need a flag:** use `sp --help`, `sp COMMAND --help`, or `man sp`.

Report reproducible problems in the [repository’s issue tracker](https://github.com/koehn/2ndPass/issues). Never include passwords, tokens, plaintext exports, or sensitive vault contents in a report.

## Offline recovery after device loss

Set up recovery before losing access to your devices:

1. Unlock 2ndPass and open **Settings → Recovery → Set Up or Verify Recovery…**.
2. Select **Generate a New Recovery Copy**.
3. Choose **Save Recovery File…** or **Print Recovery Copy…**, or write down the
   displayed code. Store your copy offline, separate from your devices and iCloud.
4. Use **Import Recovery File…** to load the saved file, or re-enter your
   written copy in **Recovery code**.
5. Select **Verify Copy and Activate**, then **Check Coverage**. If any vault is
   unfinished, select **Resume Incomplete Changes** until every vault is complete.

Recovery applies to all your owned iCloud vaults, regardless of the selected vault.

On a replacement device, sign into the same Apple Account. Open
**Settings → Recovery → Recover Vault Access…** (or choose recovery during
onboarding), then import the copy or enter its code. Read-only recovery can open healthy data while unavailable
attachments postpone completion. Complete each vault to rotate encryption and enroll the replacement device while
preserving existing devices, accounts, and roles. Keep both copies during key replacement until
coverage is complete.

The private recovery secret and copied ciphertext suffice for offline decryption;
protect the copy separately from your devices. It cannot restore Apple Account
access or missing cloud data. Account-loss recovery requires a separately exported
backup; backup restoration is outside this feature. Physical-device acceptance
and cryptographic review remain pending.

The recovery dialog first checks this device’s existing key. If it can already
open your vaults, the dialog confirms that access is working and disables recovery.
Closing setup or recovery clears the offline copy from the session without locking
the app. Explicit locking and normal security locking still clear recovery access.

### Test recovery using your existing devices

Save and verify your offline copy first. Keep it outside the app. Quit or lock
2ndPass on all other enrolled devices during the test, and stay signed into the
same Apple Account. Completing recovery preserves existing device and account access.

**With another owner device available:** Remove the test device in
**Settings → Devices**. Open the test device online so it clears its old access.
Choose **Recover with Offline Copy…** on the removed-device screen, import your
file or enter your code, browse the recovered data, and complete each vault.
Do not choose Reconnect during the test.

**With only one device available:** Open **Settings → Recovery → Set Up or Verify
Recovery…**, expand **Test recovery on this device**, and import your saved copy.
Select **Reset This Device for Recovery Testing…** and confirm. The app verifies
recovery for all owned vaults and their cloud attachments before clearing local
iCloud vault keys, cloud checkpoints, and cached iCloud data. Local-only vaults
and their keys remain unchanged. It preserves iCloud data and blocks
automatic enrollment. Enter your copy again in the recovery dialog, check your
data, then complete each vault. This cannot be undone; you need the offline copy
to regain access. If verification fails, device keys remain intact.

After either test, verify normal reads and writes, lock and restart the app, and
verify access without entering the offline copy. Repeat with the other copy
format to test both file and paper recovery. Reinstalling alone does not reliably
clear device keys. A simulator does not validate physical Secure Enclave behavior.
