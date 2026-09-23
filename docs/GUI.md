# Native Mac app

`MopApp` is a SwiftUI companion to the CLI. The signed `Mop.app` opens the native
window; `Contents/MacOS/mop` remains the CLI used by the installer and shell.
Both executables use the same signing identity, application-specific Keychain
group, CloudKit container, and existing local device state. No migration is needed.

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

- Find independent cloud vaults, select by UUID, or create a new vault. New vault
  creation saves the recovery credential first and displays the vault and device
  fingerprints. Move the recovery key offline. Creation failures retain the key
  and selected UUID for reconciliation; do not blindly repeat initialization.
- Unlock the encrypted index to browse namespaces and references. Copying a
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

The GUI honors `MOP_STATE_DIRECTORY`; inherited `MOP_CLOUD_VAULT` is ignored in
favor of visible selection. The GUI also ignores obsolete `MOP_VAULT_FILE`; use
the CLI’s explicit import workflow to migrate file-based vaults.
CloudKit access requires the same signed-device validation described in
[VALIDATION.md](VALIDATION.md). Automated tests use local process fixtures and do
not replace Touch ID, signed two-Mac enrollment, or production acceptance tests.

File import and historical revision restoration remain CLI workflows in this
version. The app deliberately has no shell/command runner.
