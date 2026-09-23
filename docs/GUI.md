# Native Mac app

`MopApp` is a SwiftUI companion to the CLI. The signed `Mop.app` opens the native
window; `Contents/MacOS/mop` remains the CLI used by the installer and shell.
Both executables use the same signing identity, application-specific Keychain
group, CloudKit container, and existing local device state. Version 0.5 requires fresh named vaults; legacy cloud data remains untouched.

## Build and open

```sh
swift build
swift test
# Set the signing variables documented in README.md, preserving your existing ID
# and CloudKit environment when upgrading.
scripts/package.sh
open dist/Mop.app
```

`swift run MopApp` can exercise the unsigned app shell, but actual vault access
still requires the provisioned bundle. Packaging includes and explicitly signs
the CLI helper before signing the enclosing application. The helper verifies its
own signing requirements and the enclosing bundle's seal. The existing installer
continues to create a symlink to `Contents/MacOS/mop`.

## Workflows

- Find named vaults, select by name, or create a new vault. UUIDs remain visible in details and can be entered explicitly. New vault
  creation saves the recovery credential first and displays the vault and device
  fingerprints. Move the recovery key offline. Creation failures retain the key
  and selected UUID for reconciliation; do not blindly repeat initialization.
- Unlock the encrypted index to browse items and their fields, grouped by optional section. Copying a
  reference does not decrypt the secret. Reveal, copy-value, create, replace,
  delete, and management operations invoke the CLI's fresh authentication.
- Secret input uses stdin, never process arguments or temporary files. Reveal
  and clipboard values expire after 30 seconds. Clipboard clearing checks the
  pasteboard change count so another application's newer content is retained.
  Secret copies are restricted to this Mac and carry a confidential-content
  marker for cooperative clipboard managers. Revealed values do not allow native
  text-selection copying; use **Copy value** so expiration applies to every copy.
  Switching apps hides the index and values but allows the copied value to be
  pasted until its timer expires. Explicit lock, sleep, and session deactivation
  also clear mop's clipboard entry. Clipboard history tools may retain copies.
- Enable **Offline snapshot** explicitly and select a vault (or enter its UUID).
  Authenticated reads show the verified snapshot's timestamp. Editing and device
  management are disabled. Synchronizing ciphertext alone does not authenticate
  or update the verified offline snapshot.
- Use **Trusted Macs** to authenticate the device list and review enrollment
  requests. Approval requires an independently obtained fingerprint, not merely
  accepting the displayed public request. Removal rotates keys and displays the
  new vault fingerprint for verification on remaining Macs.
- **Vault actions** supports enrollment requests, vault trust, recovery from an
  offline credential, and encrypted backup export. Recovery-key and backup file
  writes preserve the CLI's protected-path and no-overwrite checks.

The app does not keep an authenticated CLI session alive. It serializes commands,
keeps the UI responsive during authentication/network requests, and discards
results for a view that was locked while a command was in flight. Inactive windows
and sheets immediately hide sensitive content from display and accessibility.
Authentication can return focus before completion; a command that finishes while
the app is inactive leaves it locked and does not publish visible results. Locking does
not cancel a submitted mutation: it may still commit. Reconcile an uncertain
outcome with **Sync** before issuing another mutation. Subprocess failures are
mapped to fixed error messages; arbitrary stdout/stderr is never shown as an
error. Secret values are not logged or saved in UI preferences.

The GUI honors `MOP_STATE_DIRECTORY` and constrains CLI calls to the selected UUID.
`MOP_CLOUD_VAULT` no longer selects a vault. The GUI also ignores obsolete
`MOP_VAULT_FILE`. The CLI can import encrypted v4 backups; legacy file vaults
are no longer supported and have no migration path.
CloudKit access requires the same signed-device validation described in
[VALIDATION.md](VALIDATION.md). Automated tests use local process fixtures and do
not replace Touch ID, signed two-Mac enrollment, or production acceptance tests.

File import and historical revision restoration remain CLI workflows in this
version. The app deliberately has no shell/command runner.

## Named vault and item actions

The Vault picker displays discoverable names. These names are visible to CloudKit;
item and field names remain encrypted. **Rename vault** authenticates and commits
the new name, preserves UUID selection, then locks the index for refresh. Update
all scripts and configuration using the old name: aliases are not retained.

**New item** creates its first field. Select an item to see all fields and use
**Add field**, **Replace value**, or **Delete field**. Deleting the last field
removes the item. Item rename and whole-item delete are not available.
Offline discovery uses verified cached snapshots only, so remote renames may not
be visible. Legacy vaults appear with their UUID and require an older client.

**Vault actions → Delete vault…** supports both named and legacy vaults. Type the
name, or the full UUID for an unnamed legacy vault, then authenticate to delete
all cloud contents/history and this Mac's vault data. The dialog fixes the target
UUID and explains that backups and other Macs' caches remain. Failure or uncertain
results retain the selected target for retry; an inactive or locked view does not
publish completion into a different context. Submitted deletion may still finish.

**Export backup…** is available in Vault actions and inside the delete dialog for
supported vaults. It uses the existing authenticated CLI export, an NSSavePanel,
and the selected UUID. Offline export uses a verified snapshot. Existing output
files are not overwritten; select a new filename. Export is optional, and legacy
backups require an older client.
