# 2ndPass

An Apple-native password and developer-secrets manager. Product domain: [2ndpass.app](https://2ndpass.app).

Source repository: [koehn/2ndPass](https://github.com/koehn/2ndPass).

## Copyright and source access

Copyright © 2026 Koehn Consulting, Inc.
All rights reserved.

The 2ndPass source code is published for inspection and security review.

You may view and analyze the source code.

No license is granted to compile, execute, modify, copy, redistribute, sublicense, sell, or create derivative works from this source code.

For licensing inquiries, contact Koehn Consulting, Inc.

See the [copyright notice](LICENSE). Build, installation, and operational instructions in this repository are for the copyright holder and separately authorized users; they do not grant permission. Third-party dependencies retain their own licenses.

Formerly Mop. See [branding and upgrade compatibility](docs/BRANDING.md) for retained signing identities, settings, and legacy secret references.

2ndPass is a macOS/iOS password vault with a native app, AutoFill, and a command-line client. These clients now use independently encrypted item records in a shared device-local Core Data store. CKSyncEngine transfers committed changes through one synchronization owner per account/database. Saves are durable locally before cloud delivery.

**Development preview.** Same-account private vaults connect automatically through iCloud while an existing device is unlocked. Shared vaults, account recovery, device removal, permanent vault deletion and general document import are unavailable. See the [vault architecture](docs/VAULT.md), [backup guide](docs/BACKUPS.md) and [validation gates](docs/VALIDATION.md).

## Recent items

Recently Added, Recently Changed, and Recently Used show the newest 50 active, unarchived items across connected vaults. Search filters those 50 items. Item details show known creation, addition, change, and device-local usage times. Existing items have no invented historical dates; imports preserve source dates when available and record when they were added to 2ndPass.
Usage records successful copies, explicit reveals, AutoFill, and CLI reads (including injection and command execution). Browsing, editing preloads, OTP refreshes, and exports do not count. Usage stays in private app-group storage on this device, outside cloud synchronization and backups.
Upgrade the Mac app, iOS app, AutoFill extensions, and CLI together before editing timestamped items. This change has no feature flag or mixed-version support.
## Start or restore a vault

Open the signed app and create a vault, or restore a portable archive. Secure Enclave access requires authentication. The CLI equivalents are `sp vault init personal` and the restore command below. Other devices on the same Apple Account discover existing private vaults and connect automatically. Keep an existing device open and unlocked until key access syncs. Restoring an archive creates an independent vault; it is not how you connect another device.

## Read, write, run and inject
```sh
sp write sp://personal/service/token          # hidden prompt or stdin
sp read sp://personal/service/token
sp list --vault personal --json
sp run --env-file .env -- command arguments
sp inject --in-file template.conf --out-file rendered.conf
sp item catalog --vault personal
sp item save --vault personal < edited-item.json
```
References have the form `sp://vault/item/[section/]field`. Values are encrypted individually; listing opens the catalog only. Visible metadata such as usernames and websites is inside the encrypted catalog. Passwords, concealed fields and OTP seeds are omitted from catalog values. OTP reads return the current code. `item save` accepts an `ItemEdit` with the catalog revision, item name/type/ordered fields, `create`, and optionally `originalName`. A null field value preserves it; omitted fields are deleted. Stale edits fail.
`--vault NAME-OR-UUID` constrains selection. With multiple vaults, management commands require a selection. Names are not aliases; renaming changes references:
```sh
sp vault rename --vault VAULT_UUID new-name
sp vault sync --vault VAULT_UUID
sp read --offline sp://personal/service/token
```
Local operations use the encrypted Core Data store and a device-only account binding. They cannot detect unobserved remote revocation or prove freshness. Observed account changes invalidate that binding. GUI, CLI and AutoFill share the device-local App Group store; cloud clients no longer accept an isolated `--state-directory`. CLI writes normally wait up to 20 seconds for their exact cloud delivery receipts. Use `--local-save` to return after the durable local commit; `--offline` prevents network use. A delivery timeout leaves the local save queued and exits nonzero with receipt IDs and a pending message; do not repeat the write. GUI saves report local durability, not an unconfirmed cloud upload.
The GUI retains an authenticated session context until lock/expiry, while releasing hardware key handles and individual secret keys after operations. CLI commands own their session. AutoFill always starts fresh authentication and locks after filling. Plaintext necessarily reaches 2ndPass, clipboard destinations, and commands receiving secrets.
`read` releases plaintext to stdout or a selected file; `inject` produces plaintext configuration on stdout or disk. `run` supplies plaintext environment variables to a child: that program, its dependencies and inheriting descendants become trusted with the secret. Environments can leak through diagnostics or privileged host access. Default masking only filters exact secret bytes in stdout/stderr; it does not constrain transformed output, files or network traffic. 2ndPass cannot control a child's use of plaintext. See [CLI boundaries](docs/SECURITY.md#cli-and-extension-disclosure-boundaries).
## Recovery

Use portable backups and retain their separate archive keys. Account recovery is unavailable. Same-account device connection is automatic; no access request, approval screen or comparison code is needed.

## Backups and deletion
Portable backups contain transferable vault contents and use a newly generated
key. Keep that key separately from the archive; both are needed to restore into
a new owned vault, even without the original device keys or cloud vault.

```sh
sp vault backup --offline --vault VAULT_UUID /path/vault.moparchive --key-file /separate/path/vault.key
sp vault restore-backup /path/vault.moparchive --key-file /separate/path/vault.key --name restored --restore-id NEW_UUID --dry-run
sp vault restore-backup /path/vault.moparchive --key-file /separate/path/vault.key --name restored --restore-id NEW_UUID
```

Generate and retain a fresh restore UUID for retries. Restore does not reinstate
sharing or export Secure Enclave private keys. Keep the original vault until you
have verified the restored contents. See the [backup guide](docs/BACKUPS.md)
for format limits and acceptance gates.

The service exports a locally stored snapshot (also available with `--offline`); it cannot yet certify a complete remote inventory. Keep the original archive until restored contents have been checked. Its wire format, key encoding, validation limits and restoration semantics are defined in the [standalone specification](docs/formats/PORTABLE-BACKUP-v1.md). Permanent cloud-vault deletion is unavailable.

## Build and provision

These instructions require separate authorization from Koehn Consulting, Inc. The published source grants inspection and analysis rights only.

```sh
swift build
swift test
```
Unsigned builds support help, completions, and commands without secret references. Operational access requires a signed bundle. Keep the application identifier, signing team, and CloudKit container stable across upgrades.
1. Register an explicit macOS App ID (default `com.koehn.mop`). Enable iCloud with CloudKit and the application-specific Keychain access group.
2. Associate the container `iCloud.<bundle identifier>` with the App ID.
3. Generate a provisioning profile authorizing that container and the selected CloudKit environment. Create the schema described in [CloudKit setup](docs/CLOUDKIT.md).
4. Package the application:
```sh
export MOP_SIGN_IDENTITY='Your Apple signing identity'
export MOP_PROVISION_PROFILE='/path/to/profile.provisionprofile'
export MOP_AUTOFILL_PROVISION_PROFILE='/path/to/AutoFill.provisionprofile'
export MOP_CLI_PROVISION_PROFILE='/path/to/CLI.provisionprofile'
export MOP_BUNDLE_ID='com.koehn.mop'
export MOP_CLOUD_ENVIRONMENT='Development' # Production for release builds
scripts/package-cli.sh
scripts/install-cli.sh
scripts/package.sh
scripts/install.sh dist/2ndPass.app
open /Applications/2ndPass.app
sp vault list
```
The GUI installer places the sandboxed app at `/Applications/2ndPass.app`; it contains no CLI. The separate CLI installer places its signed bundle under `/usr/local/lib/sp` and links `/usr/local/bin/sp`, manpages, and completions. Set `MOP_INSTALL_ROOT` for a different CLI prefix, or `MOP_APPLICATIONS_DIR` for a different GUI destination. Install the CLI before upgrading an older combined app so its shell link continues to work.

Register a separate `com.koehn.mop.CLI` App ID with access to the existing host Keychain group, App Group, and CloudKit container. The host and AutoFill extension need their AutoFill capability and shared App Group as well. See [CLI provisioning and Homebrew releases](docs/HOMEBREW.md) for exact capabilities and notarized release commands. Both packages default to Production and reject profiles that do not authorize the requested resources. Keep the CLI inside its own signed bundle; expose it through a symlink.

## Platform checks
`sp-keychain-check --run` explicitly creates and retains a uniquely scoped disposable hardware identity and verifies opaque Keychain reload and signing. See [validation](docs/VALIDATION.md) for automated and physical-device acceptance requirements. Do not treat software fixtures or simulator builds as hardware evidence.
## Current limitations

Cross-account sharing, recovery and document imports require further integration. Cloud software credential bytes can survive portable restore, but account registration management is not yet connected. The separate `local` vault and its hardware-backed operations remain available.

## Public website and build shortcuts

The public [2ndPass website](website/README.md) lives in `website/`, built with
Eleventy from Markdown and shared templates. With Node.js 22+, Python 3.10+, and
[just](https://just.systems/) installed:

```sh
just site-install
just site-build
just site-serve
```

`just --list` shows app/CLI builds, tests, packaging, iOS archives, and S3 deployment
recipes. `just site-deploy-dry-run BUCKET` prints the deployment plan without making
AWS calls. See the [website guide](website/README.md#deploy-to-s3) for HTTPS hosting
and deployment configuration.

### Cloud and device-local capabilities

See the website’s [vault capability comparison](https://2ndpass.app/docs.html#vault-capabilities)
for supported secret types, key operations, synchronization, and recovery by vault type.


Cloud vaults support software passkeys and generated/imported SSH keys through item reads and saves. Credential-account registration management remains unavailable; cloud-key physical acceptance is still required. See [cloud key credentials](docs/CLOUD-KEY-CREDENTIALS.md)
for supported formats, SSH/Git setup, protection, sharing, and outstanding acceptance.

The vault named exactly `local` holds Secure Enclave SSH, Git signing, certificate,
and device-bound passkey identities. Private keys never leave this device and cannot
be synced, exported, backed up, or restored. Register independent credentials on
another device before relying on them. See [local vault usage, passkey platform
limitations, and acceptance requirements](docs/LOCAL-VAULT.md).

Subscription status reporting and release configuration are documented in
[Subscription evidence](docs/SUBSCRIPTIONS.md). This preview does not enforce
Free/Pro limits; purchase UI and production publication default to disabled.
