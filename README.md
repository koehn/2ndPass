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

2ndPass is a macOS/iOS password vault with a native app, AutoFill, and a command-line client. Personal and shared vaults use the same v7 format. Each device has independent Secure Enclave keys; signing in alone does not grant decryption access; an unlocked enrolled owner can automatically grant same-account membership through the provisioned private CloudKit channel.

**This is a coordinated format replacement.** There is no old-format reader, migration, synchronized software device key. Offline recovery uses an explicitly exported private recovery copy. Existing files, cloud zones, backups and Keychain items are left untouched. Keep a compatible older client separately if you still need old data.

Read [the plain-language security explanation](docs/SECURITY-EXPLAINER.md), [architecture](docs/VAULT-NEXT.md), and [concrete validation results and outstanding physical checks](docs/VAULT-NEXT-VALIDATION.md). Cross-account vault sharing is not yet implemented as a supported feature; preliminary code requires completion, mailbox isolation and two-account acceptance.

## Recent items

Recently Added, Recently Changed, and Recently Used show the newest 50 active, unarchived items across connected vaults. Search filters those 50 items. Item details show known creation, addition, change, and device-local usage times. Existing items have no invented historical dates; imports preserve source dates when available and record when they were added to 2ndPass.
Usage records successful copies, explicit reveals, AutoFill, and CLI reads (including injection and command execution). Browsing, editing preloads, OTP refreshes, and exports do not count. Usage stays in private app-group storage on this device, outside cloud synchronization and backups.
Upgrade the Mac app, iOS app, AutoFill extensions, and CLI together before editing timestamped items. This change has no feature flag or mixed-version support.
## Start a vault
Open the signed Mac, iPhone or iPad app. If no v7 vaults exist in iCloud, 2ndPass prompts you to create one. Choose a name and authenticate: this device’s Secure Enclave keys are generated automatically, and you can save secrets immediately.
The CLI equivalent is:
```sh
sp vault init personal
```

```sh
# New device (use the UUID shown by vault list):
sp vault enrollment request --vault VAULT_UUID --name 'My Mac'
# Existing owner device:
sp vault enrollment inbox --vault personal
# New device: receive the invitation and send acceptance:
sp vault enrollment status --vault VAULT_UUID
# After comparing both displays, confirm on the new device:
sp vault enrollment confirm --vault VAULT_UUID --code MATCHING_CODE
# Existing owner: refresh inbox and approve:
sp vault enrollment inbox --vault personal
sp vault enrollment approve --vault personal --request-id REQUEST_UUID --code MATCHING_CODE
# New device: finish enrollment:
sp vault enrollment status --vault VAULT_UUID
```
`enrollment decline --request-id REQUEST_UUID` declines a request. On the new device, `enrollment restart --vault VAULT_UUID` sends a fresh request while preserving its keys; `enrollment cancel --vault VAULT_UUID` cancels the pending request. The app provides Restart connection, Cancel request, visible progress and the last successful iCloud check. All operations require online access. Only enrolled owners can approve. CLI status checks are explicit; the app polls automatically while active and authorized.
For another account, or advanced manual enrollment:
On the new device:
```sh
sp device request > device-request.json
```
On an owner device, independently compare the request fingerprint:
```sh
sp vault invite --vault personal device-request.json --fingerprint REQUEST_FINGERPRINT --role editor > invitation.json
```
Use `--role owner` only for another device on the existing owner account. Other accounts can be editors or viewers. The invitation's checkpoint and, for another account, private iCloud share URL are printed to stderr. Transfer them and compare the checkpoint independently.
On the new device:
```sh
sp vault accept invitation.json --checkpoint VERIFIED_CHECKPOINT --share-url ICLOUD_SHARE_URL > acceptance.json
```
Omit `--share-url` for another device on the same account. Return acceptance to the owner:
```sh
sp vault approve --vault personal acceptance.json --fingerprint REQUEST_FINGERPRINT
sp vault members --vault personal
```
Refresh on the receiving device. Invitations expire after one day in the clients and bind the exact checkpoint. If another write wins before approval, issue a fresh invitation; do not overwrite the competing revision.
```sh
sp vault remove-device --vault personal DEVICE_UUID
sp vault remove-member --vault personal ACCOUNT_UUID
sp vault role --vault personal ACCOUNT_UUID viewer
sp vault reconcile-share --vault personal
```
Removal rotates keys and ciphertext for current contents. The final command retries CloudKit permissions after a roster change if its separate transport update failed. Copied passwords, prior ciphertext and old backups cannot be revoked.
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
Offline access uses a previously verified encrypted checkpoint and is read-only. It cannot detect remote revocation or prove freshness. Observed account changes invalidate offline account bindings. Local state must never be synchronized: packaged app/CLI/AutoFill share a device-local app-group directory; the CLI permits `--state-directory` or `MOP_STATE_DIRECTORY` for explicit isolation.
The GUI retains an authenticated session context until lock/expiry, while releasing hardware key handles and individual secret keys after operations. CLI commands own their session. AutoFill always starts fresh authentication and locks after filling. Plaintext necessarily reaches 2ndPass, clipboard destinations, and commands receiving secrets.
`read` releases plaintext to stdout or a selected file; `inject` produces plaintext configuration on stdout or disk. `run` supplies plaintext environment variables to a child: that program, its dependencies and inheriting descendants become trusted with the secret. Environments can leak through diagnostics or privileged host access. Default masking only filters exact secret bytes in stdout/stderr; it does not constrain transformed output, files or network traffic. 2ndPass cannot control a child's use of plaintext. See [CLI boundaries](docs/SECURITY.md#cli-and-extension-disclosure-boundaries).
## Offline recovery
Set up an offline master recovery copy while you can access your vaults. In the app,
choose **Manage Offline Recovery**, generate a copy, save it offline or write down
the displayed code, then re-import or re-enter it to activate protection.

```sh
sp vault recovery generate --output /Volumes/OFFLINE/2ndpass-recovery.txt
sp vault recovery activate --file /Volumes/OFFLINE/2ndpass-recovery.txt --fingerprint PUBLIC_FINGERPRINT
sp vault recovery status
```

If all enrolled devices are unavailable, sign into the **same Apple Account** on a
replacement device, choose **Recover an existing vault**, and enter the offline
code or import the file. No surviving device or locally retained checkpoint is
required. Open read-only access first, then complete recovery for each vault.

```sh
sp vault recovery open --file /Volumes/OFFLINE/2ndpass-recovery.txt
sp vault recovery open --file /Volumes/OFFLINE/2ndpass-recovery.txt --complete
sp vault recovery resume
sp vault recovery revoke
```

During replacement, keep both offline copies until coverage is complete. A missing
attachment can postpone completion while healthy data remains readable. Existing
devices and accounts remain connected after completion. The code cannot recover your
Apple Account or missing cloud data. Loss of the account requires a separately
exported backup; backup restoration is outside this feature. See
[the recovery security model](docs/SECURITY.md#recovery-and-backups).

## Backups and deletion
Export returns an encrypted v7 checkpoint; record its digest independently. Import requires that digest and an already enrolled device. For a shared-database checkpoint, also supply `--shared-owner` with its actual zone owner record name. Import never creates or overwrites a cloud zone.
```sh
sp vault delete --vault VAULT_UUID --confirm VAULT_UUID
```
Deletion requires owner authorization, removes the cloud zone, and forgets its active registry entry. Existing local ciphertext and exported backups remain. Old-format data cannot be selected or deleted through v7 commands.
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
export MOP_BUNDLE_ID='com.koehn.mop'
export MOP_CLOUD_ENVIRONMENT='Development' # Production for release builds
scripts/package.sh
scripts/install.sh dist/2ndPass.app
open /Applications/2ndPass.app
sp vault list
```
The installer places the app at `/Applications/2ndPass.app` and links the CLI at `/usr/local/bin/sp`. It requests administrator access only when needed for file installation. Run the script as your normal user. Manpages and completions go under `/usr/local/share`; ensure `/usr/local/bin` is on your PATH. If an older installation at `~/.local/bin/sp` takes precedence, remove that old symlink or place `/usr/local/bin` earlier in PATH; check with `command -v sp`. Existing vault state is preserved by the installer. For isolated test installs, set both `MOP_INSTALL_ROOT` (CLI/resources prefix) and `MOP_APPLICATIONS_DIR`.
Packaging defaults to `Production` and rejects profiles without the matching CloudKit environment/container. It emits only the narrow Keychain and CloudKit entitlements, without debugging exceptions. Moving the executable out of its app bundle breaks access; the installer uses a symlink to the bundled executable. Developer profiles/environments are distinct from production data
## Platform checks
`sp-keychain-check --run` explicitly creates and retains a uniquely scoped disposable hardware identity and verifies opaque Keychain reload and signing. See [validation](docs/VAULT-NEXT-VALIDATION.md) for live CloudKit/Enclave probes, modeled scenarios and checks still requiring separate physical devices/accounts. Do not treat software fixtures or simulator builds as hardware evidence.
## Remove a device or repeat enrollment testing
On macOS, iOS, and iPadOS, **Settings → devices → Remove…** revokes the selected device across your personal vaults enrolled on the managing device. Removal rotates encryption material and retires the old device UUID. The removed device clears local access when it next verifies the removal online, then offers **Reconnect** instead of enrolling automatically. Reconnection creates fresh device keys. The final owner device cannot be removed.
CLI equivalents for repeatable testing:
```sh
sp vault devices
sp vault devices --remove DEVICE_UUID
# On the removed device, detect revocation:
sp vault sync --vault VAULT_UUID
# Explicitly opt back in, then request enrollment:
sp vault enrollment reconnect
sp vault enrollment request --vault VAULT_UUID --name "Test iPad"
```

Keep another enrolled device unlocked to complete the new request.

## Import from another password manager

Use **Import…** in the app, or `sp item import FILE --vault personal --dry-run`
to preview a supported export. See [Importing password-manager data](docs/IMPORT.md)
for supported formats, conflict handling, and migration limits.

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

### Device-local identities

Cloud vaults support usable passkeys and generated/imported SSH keys. Choose storage
explicitly when creating a credential. See [cloud key credentials](docs/CLOUD-KEY-CREDENTIALS.md)
for supported formats, SSH/Git setup, protection, sharing, and outstanding acceptance.

The vault named exactly `local` holds Secure Enclave SSH, Git signing, certificate,
and device-bound passkey identities. Private keys never leave this device and cannot
be synced, exported, backed up, or restored. Register independent credentials on
another device before relying on them. See [local vault usage, passkey platform
limitations, and acceptance requirements](docs/LOCAL-VAULT.md).
