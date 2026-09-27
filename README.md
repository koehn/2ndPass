# Mop

Source repository: [koehn/2ndPass](https://github.com/koehn/2ndPass).

## Copyright and source access

Copyright © 2026 Koehn Consulting, Inc.
All rights reserved.

The 2ndPass source code is published for inspection and security review.

You may view and analyze the source code.

No license is granted to compile, execute, modify, copy, redistribute, sublicense, sell, or create derivative works from this source code.

For licensing inquiries, contact Koehn Consulting, Inc.

See the [copyright notice](LICENSE). Build, installation, and operational instructions in this repository are for the copyright holder and separately authorized users; they do not grant permission. Third-party dependencies retain their own licenses.

Mop is a macOS/iOS password vault with a native app, AutoFill, and a command-line client. Personal and shared vaults use the same v6 format. Each device has independent Secure Enclave keys; signing into an Apple Account does not enroll a device.

**This is a coordinated format replacement.** There is no old-format reader, migration, synchronized software private key, or portable recovery private key. Existing files, cloud zones, backups and Keychain items are left untouched. Keep a compatible older client separately if you still need old data.

Read [the plain-language security explanation](docs/SECURITY-EXPLAINER.md), [architecture](docs/VAULT-NEXT.md), and [concrete validation results and outstanding physical checks](docs/VAULT-NEXT-VALIDATION.md). Cross-account sharing code is implemented; actual participant-side acceptance with a second Apple Account remains a required release check.

## Start a vault

Open the signed Mac, iPhone or iPad app. If no v6 vaults exist in iCloud, Mop
prompts you to create one. Choose a name and authenticate: this device’s Secure
Enclave keys are generated automatically, and you can save secrets immediately.
The CLI equivalent is:

```sh
mop vault init personal
```

Recovery is optional. Until another device or hardware recovery is added, losing
this device means losing access. No second device is required for creation.

If v6 vaults exist in iCloud but this device has no trusted enrollment, Mop opens
**Connect this device** instead. Discovery is only a hint: it neither trusts a
checkpoint nor grants decryption rights. A CloudKit failure is reported, not
treated as an empty account. Old-format zones are ignored and preserved.

For another device on your Apple Account, Mop automatically submits an enrollment
request through iCloud. Open Mop on any enrolled owner device and unlock it.
The unlocked owner device quietly grants access. The new device shows progress
and opens its vault automatically. Existing devices show an in-app notice when
they next check the signed membership. No comparison or confirmation is required.
If all existing devices are locked, unlock Mop on one of them.

Same-account enrollment now trusts access to the private iCloud mailbox for
bootstrap identity. An attacker with that account access can enroll while an
owner device is unlocked. Secure Enclave private keys still never transfer.
Cross-account sharing does not use automatic enrollment.

Sharing with another account remains a separate **Share with another person**
flow with editor/viewer permissions and file-based invitations.

## Add optional recovery later

Use **Set up or replace hardware recovery** in Settings → vault. On a separate
recovery device, create its public recovery request; import that request on the
owner device and compare its fingerprint. Existing secret keys are wrapped for
the recovery device. Replacing an existing recovery device rotates current keys.
The CLI equivalent is:

```sh
# On the recovery device:
mop device request --recovery > recovery-request.json
# On the owner device:
mop vault replace-recovery --vault personal recovery-request.json --fingerprint VERIFIED_REQUEST_FINGERPRINT
mop vault export --vault personal personal-backup.json
mop vault fingerprint --vault personal
```

Retain the encrypted backup and independently recorded checkpoint. Recovery,
when configured, remains hardware-only; there is no software recovery key.
Losing every authorized device and any configured recovery device makes the
vault unrecoverable. Optional recovery can also be supplied during CLI creation
with paired `--recovery-request` and `--fingerprint` options.

## Add devices and share

The app handles own-account enrollment automatically. CLI equivalents are:

```sh
# New device (use the UUID shown by vault list):
mop vault enrollment request --vault VAULT_UUID --name 'My Mac'
# Existing owner device:
mop vault enrollment inbox --vault personal
# New device: receive the invitation and send acceptance:
mop vault enrollment status --vault VAULT_UUID
# After comparing both displays, confirm on the new device:
mop vault enrollment confirm --vault VAULT_UUID --code MATCHING_CODE
# Existing owner: refresh inbox and approve:
mop vault enrollment inbox --vault personal
mop vault enrollment approve --vault personal --request-id REQUEST_UUID --code MATCHING_CODE
# New device: finish enrollment:
mop vault enrollment status --vault VAULT_UUID
```

`enrollment decline --request-id REQUEST_UUID` declines a request. On the new
device, `enrollment restart --vault VAULT_UUID` sends a fresh request while
preserving its keys; `enrollment cancel --vault VAULT_UUID` cancels the pending
request. The app provides Restart connection, Cancel request, visible progress
and the last successful iCloud check. All operations
require online access. Only enrolled owners can approve. CLI status checks are
explicit; the app polls automatically while active and authorized.

For another account, or advanced manual enrollment:

On the new device:

```sh
mop device request > device-request.json
```

On an owner device, independently compare the request fingerprint:

```sh
mop vault invite --vault personal device-request.json --fingerprint REQUEST_FINGERPRINT --role editor > invitation.json
```

Use `--role owner` only for another device on the existing owner account. Other accounts can be editors or viewers. The invitation's checkpoint and, for another account, private iCloud share URL are printed to stderr. Transfer them and compare the checkpoint independently.

On the new device:

```sh
mop vault accept invitation.json --checkpoint VERIFIED_CHECKPOINT --share-url ICLOUD_SHARE_URL > acceptance.json
```

Omit `--share-url` for another device on the same account. Return acceptance to the owner:

```sh
mop vault approve --vault personal acceptance.json --fingerprint REQUEST_FINGERPRINT
mop vault members --vault personal
```

Refresh on the receiving device. Invitations expire after one day in the clients and bind the exact checkpoint. If another write wins before approval, issue a fresh invitation; do not overwrite the competing revision.

```sh
mop vault remove-device --vault personal DEVICE_UUID
mop vault remove-member --vault personal ACCOUNT_UUID
mop vault role --vault personal ACCOUNT_UUID viewer
mop vault reconcile-share --vault personal
```

Removal rotates keys and ciphertext for current contents. The final command retries CloudKit permissions after a roster change if its separate transport update failed. Copied passwords, prior ciphertext and old backups cannot be revoked.

## Read, write, run and inject

```sh
mop write mop://personal/service/token          # hidden prompt or stdin
mop read mop://personal/service/token
mop list --vault personal --json
mop run --env-file .env -- command arguments
mop inject --in-file template.conf --out-file rendered.conf
mop item catalog --vault personal
mop item save --vault personal < edited-item.json
```

References have the form `mop://vault/item/[section/]field`. Values are encrypted individually; listing opens the catalog only. Visible metadata such as usernames and websites is inside the encrypted catalog. Passwords, concealed fields and OTP seeds are omitted from catalog values. OTP reads return the current code. `item save` accepts an `ItemEdit` with the catalog revision, item name/type/ordered fields, `create`, and optionally `originalName`. A null field value preserves it; omitted fields are deleted. Stale edits fail.

`--vault NAME-OR-UUID` constrains selection. With multiple vaults, management commands require a selection. Names are not aliases; renaming changes references:

```sh
mop vault rename --vault VAULT_UUID new-name
mop vault sync --vault VAULT_UUID
mop read --offline mop://personal/service/token
```

Offline access uses a previously verified encrypted checkpoint and is read-only. It cannot detect remote revocation or prove freshness. Observed account changes invalidate offline account bindings. Local state must never be synchronized: packaged app/CLI/AutoFill share a device-local app-group directory; the CLI permits `--state-directory` or `MOP_STATE_DIRECTORY` for explicit isolation.

The GUI retains an authenticated session context until lock/expiry, while releasing hardware key handles and individual secret keys after operations. CLI commands own their session. AutoFill always starts fresh authentication and locks after filling. Plaintext necessarily reaches Mop, clipboard destinations, and commands receiving secrets.

## Hardware recovery

Generate ordinary and recovery requests on the replacement owner device and a new separate recovery device. Compare both fingerprints. On the **currently enrolled recovery device**:

```sh
mop vault recover backup.json --checkpoint VERIFIED_BACKUP_CHECKPOINT \
  --owner-request new-owner.json --owner-fingerprint VERIFIED_OWNER_REQUEST \
  --recovery-request new-recovery.json --recovery-fingerprint VERIFIED_RECOVERY_REQUEST > recovered.json
```

This verifies newer signed descendants when the account is still available, then replaces the old roster. On the replacement owner device, import the returned checkpoint using the independently transmitted new digest:

```sh
mop vault import recovered.json --checkpoint VERIFIED_NEW_CHECKPOINT
```

If account access is lost, use `--copy` on the recovery device signed into the new account. First generate that device's ordinary request for `--owner-request`. This creates a new vault UUID/root under the new account and preserves the source. Then enroll additional devices normally. No software recovery key is imported or exported.

## Backups and deletion

Export returns an encrypted v6 checkpoint; record its digest independently. Import requires that digest and an already enrolled device. For a shared-database checkpoint, also supply `--shared-owner` with its actual zone owner record name. Import never creates or overwrites a cloud zone.

```sh
mop vault delete --vault VAULT_UUID --confirm VAULT_UUID
```

Deletion requires owner authorization, removes the cloud zone, and forgets its active registry entry. Existing local ciphertext and exported backups remain. Old-format data cannot be selected or deleted through v6 commands.

## Build and provision

These instructions require separate authorization from Koehn Consulting, Inc. The published source grants inspection and analysis rights only.

```sh
swift build
swift test
```

Unsigned builds support help, completions, and commands without secret references.
Operational access requires a signed bundle. Keep the application identifier,
signing team, and CloudKit container stable across upgrades.

1. Register an explicit macOS App ID (default `com.koehn.mop`). Enable iCloud with
   CloudKit and the application-specific Keychain access group.
2. Associate the container `iCloud.<bundle identifier>` with the App ID.
3. Generate a provisioning profile authorizing that container and the selected
   CloudKit environment. Create the schema described in [CloudKit setup](docs/CLOUDKIT.md).
4. Package the application:

```sh
export MOP_SIGN_IDENTITY='Your Apple signing identity'
export MOP_PROVISION_PROFILE='/path/to/profile.provisionprofile'
export MOP_BUNDLE_ID='com.koehn.mop'
export MOP_CLOUD_ENVIRONMENT='Development' # Production for release builds
scripts/package.sh
scripts/install.sh dist/Mop.app
open /Applications/Mop.app
mop vault list
```

The installer places the app at `/Applications/Mop.app` and links the CLI at
`/usr/local/bin/mop`. It requests administrator access only when needed for file
installation. Run the script as your normal user. Manpages and completions go under
`/usr/local/share`; ensure `/usr/local/bin` is on your PATH. If an older installation
at `~/.local/bin/mop` takes precedence, remove that old symlink or place
`/usr/local/bin` earlier in PATH; check with `command -v mop`. Existing vault state
is preserved by the installer. For isolated test installs,
set both `MOP_INSTALL_ROOT` (CLI/resources prefix) and `MOP_APPLICATIONS_DIR`.

Packaging defaults to `Production` and rejects profiles without the matching
CloudKit environment/container. It emits only the narrow Keychain and CloudKit
entitlements, without debugging exceptions. Moving the executable out of its app
bundle breaks access; the installer uses a symlink to the bundled executable.
Developer profiles/environments are distinct from production data.


## Platform checks

`mop-keychain-check --run` explicitly creates and retains a uniquely scoped disposable hardware identity and verifies opaque Keychain reload and signing. See [validation](docs/VAULT-NEXT-VALIDATION.md) for live CloudKit/Enclave probes, modeled scenarios and checks still requiring separate physical devices/accounts. Do not treat software fixtures or simulator builds as hardware evidence.

## Remove a device or repeat enrollment testing

On macOS, iOS, and iPadOS, **Settings → devices → Remove…**
revokes the selected device across your personal vaults enrolled on the managing
device. Removal rotates encryption material and retires the old device UUID.
The removed device clears local access when it next verifies the removal online,
then offers **Reconnect** instead of enrolling automatically. Reconnection
creates fresh device keys. The final owner device cannot be removed.

CLI equivalents for repeatable testing:

```sh
mop vault devices
mop vault devices --remove DEVICE_UUID
# On the removed device, detect revocation:
mop vault sync --vault VAULT_UUID
# Explicitly opt back in, then request enrollment:
mop vault enrollment reconnect
mop vault enrollment request --vault VAULT_UUID --name "Test iPad"
```

Keep another enrolled device unlocked to complete the new request.

## Import from another password manager

Use **Import…** in the app, or `mop item import FILE --vault personal --dry-run`
to preview a supported export. See [Importing password-manager data](docs/IMPORT.md)
for supported formats, conflict handling, and migration limits.
