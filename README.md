# mop

Source repository: [koehn/2ndPass](https://github.com/koehn/2ndPass).

## Copyright and source access

Copyright © 2026 Koehn Consulting, Inc.
All rights reserved.

The 2ndPass source code is published for inspection and security review.

You may view and analyze the source code.

No license is granted to compile, execute, modify, copy, redistribute, sublicense, sell, or create derivative works from this source code.

For licensing inquiries, contact Koehn Consulting, Inc.

See the [copyright notice](LICENSE). Build, installation, and operational instructions in this repository are for the copyright holder and separately authorized users; they do not grant permission. Third-party dependencies retain their own licenses.

mop is a macOS secret manager with a native Mac app, a command-line interface, CloudKit synchronization, and
account identities synchronized through iCloud Keychain. It supplies credentials to commands and templates
using references such as `mop://personal/service/token`.

**CloudKit implementation: signed two-Mac and production acceptance are still
required before release.** See [validation](docs/VALIDATION.md).

Requires macOS 15+ or iOS/iPadOS 18+, an Apple Account with iCloud Passwords &
Keychain enabled, and a provisioned signed application. See the
[account identity and membership model](docs/ACCOUNT-IDENTITY.md).

## Native Mac app

Open the packaged `Mop.app` to browse secrets, copy references, view account
membership, create vaults, and export encrypted backups. The app authenticates once per
session across owned vaults and locks after configurable inactivity (1–60
minutes, default 5). It calls the native vault libraries using the synchronized account
identity. Both apps start locked and automatically authenticate all connected vaults together.
Interaction resets the timeout; switching apps retains the session until it expires.
Unconnected vaults have a distinct icon. A collapsible vault
sidebar and All Vaults view keep items organized; editing supports inline item
renaming and password-strength indicators. Offline browsing is explicit and read only. See [the Mac app guide](docs/GUI.md).

```sh
open dist/Mop.app
```

## Password AutoFill

Mop includes an iOS/macOS AutoFill extension. Enable Mop in system AutoFill settings,
then open and unlock the app to publish website/username suggestions. System AutoFill
handles authentication for suggested credentials; choosing “Mop…” opens its picker
with Mop authentication. Both read a shared encrypted snapshot and work offline.
See [AutoFill setup and provisioning](docs/AUTOFILL.md).

## Item templates and field types

**New item** offers Login, Password, API credential, Secure note, and Database
templates. **Edit item** changes the item/field types, adds or removes fields,
and moves fields up or down. Order is saved with the item and synchronized across Macs.

Username, website, email, text, and notes fields are visible after unlocking the
index. Password and concealed fields remain hidden until explicitly read. The CLI
authenticates each command; the GUI reuses its unlocked session.
All values remain encrypted in storage, backups, and iCloud. OTP fields display
the current time-based code. CLI reads, template injection, and environment
reference substitution return that code rather than the seed or provisioning URL.

Existing untyped fields default to concealed in a Custom item. Only v5 vaults and
backups are supported. Older formats are rejected; no conversion is provided.

`mop item catalog --vault personal` returns JSON with the current revision, item
and field types, saved order, and visible values (never concealed values).
`mop item save --vault personal` accepts an `ItemEdit` JSON object through stdin:
`revision`, `create` (boolean), and `item` (`name`, `type`, ordered `fields`). Each
field has `path` (canonical percent-encoded `field` or `section/field`), `type`, and
an optional `value`. An omitted/null value preserves an existing value; an empty
string replaces it with empty text. Fields omitted from an existing item's edit
are deleted. Stale revisions fail without overwriting another writer. Ordinary
`mop list --json` still returns references only.

## Storage and authentication

Mop encrypts each vault using `mop-vault-v5`, with independent AES-GCM keys
wrapped for its account owner and offline recovery credential. The owner's
synchronized identity signs membership and every revision. CloudKit stores
immutable ciphertext and publishes changes with conditional, journaled commits.

The app authenticates once per session; CLI secret commands authenticate per
command. Account private keys synchronize through iCloud Keychain and are not
Secure Enclave keys. Legacy device credentials are not used. Account access replaces enrollment and pairing.

Each named vault has its own stable UUID, CloudKit zone, signed membership, recovery
credential, and trust fingerprint. In `mop://personal/service/token`, `personal`
selects that encrypted vault, `service` is an item, and `token` is a field.
Vault names are discoverable metadata visible to CloudKit; item/field names and
values remain encrypted. Names use 1–63 lowercase ASCII letters/digits with
single internal hyphens. Multiple independent vaults are supported. Cross-account sharing is not yet
implemented; each zone is private to its owner's Apple Account.

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

## Create and select a vault

```sh
mop vault init personal --recovery-file "$HOME/mop-recovery.key"
mop vault list
mop vault use VAULT_UUID
```

Initialization prints the vault UUID, account identity, and vault fingerprint.
Move the recovery file offline and retain the vault fingerprint with it. The
recovery credential is a full alternative decryption capability: never put it
in CloudKit or keep it next to a synchronized backup. A failed initialization
retains any recovery file already written.

References select their vault by name, independent of any saved default.
`mop list` lists all owned named vaults with one authentication per command;
`mop list --vault personal` selects one.
Use `--vault NAME-OR-UUID` to constrain a reference command or select a management
command's vault. `vault use` saves an account-scoped default for management only.
A missing or ambiguous name is an error, never a fallback to another vault.
`--cloud-vault` has been removed; `MOP_CLOUD_VAULT` no longer selects a vault.
A new device discovers owned vaults after its account identity arrives through iCloud Keychain.
`vault list --json` returns descriptors with `id`, `name`, `format`, and `enrolled`.
The retained JSON field `enrolled` means that the account identity is a member;
it does not describe per-device enrollment.
Discovery names/membership claims are unverified until authentication.

```sh
mop vault rename personal private
mop vault rename VAULT_UUID personal   # also resolves a duplicate-name conflict
```

Renaming keeps the UUID, keys, records, and recovery credentials. Update references
in scripts and configuration: there are no old-name aliases. Offline reads use
names from verified snapshots and may retain an old name until reconnecting.
Concurrent creation/rename on separate Macs can produce duplicate names; select
by UUID to rename one. Name availability checks do not provide a global lock.

Only v5 vaults and backups are accepted. Existing v5 vaults remain supported,
including ones converted by an older release. Pre-v5 vaults, credentials, and
history have no supported conversion/access path. Existing cloud data is left
untouched; use an older compatible client separately if you need that data.

### Delete a vault

```sh
mop vault delete personal       # type its name, then authenticate
mop vault delete LEGACY_UUID    # type the UUID for an unnamed legacy vault
mop vault delete VAULT_UUID --yes  # skip typing; authentication still required
```

Deletion permanently removes the entire cloud zone, including history and staged
records. It also clears that vault's local cache/trust and its saved default, if
selected. The shared account identity and Keychain keys are preserved. Exported backups
and caches on other Macs remain. Offline deletion is refused. Legacy deletion by
UUID does not require decrypting the old format or being a member of that vault.

The GUI offers **Export backup…** and **Delete vault…** under **Vault actions**.
The delete dialog requires typing the name (UUID for legacy vaults) and offers
backup export for supported vaults. Use an older client to back up legacy data.
No backup is forced. Exported backups remain encrypted; retain recovery credentials.

`--yes` is required without a terminal and only bypasses typed confirmation. If
the outcome is uncertain, local data is retained; retry with the same UUID to
reconcile. Exit 27 means remote deletion could not be confirmed; exit 28 means
remote deletion succeeded but local cleanup needs retrying. Mop checks remote
absence before local cleanup and never automatically repeats a delete request.

Local metadata defaults to `~/Library/Application Support/Mop`, overridden by `--state-directory` or
`MOP_STATE_DIRECTORY`. **Never synchronize this directory.** It contains account-scoped
ciphertext caches, commit journals, and trust pins.
Account private keys live in iCloud Keychain. Old device metadata is ignored;
removing legacy support does not delete existing files or Keychain items.
Secret output cannot target the state directory.

Older macOS versions used `~/.mop`. Before first launching this version, quit Mop
and stop any running CLI commands, then move that directory to
`~/Library/Application Support/Mop` if the destination does not already exist.
This preserves cached vaults, trust pins, pending operations, and the default
vault selection. If both directories already exist, do not overwrite either;
use `MOP_STATE_DIRECTORY` to select the existing state explicitly. The app does
not automatically migrate or merge state directories.

## Use another Mac, iPhone, or iPad

Sign into the same Apple Account, enable iCloud Passwords & Keychain, and open Mop.
Owned vaults appear automatically once the identity reaches the device. There is
no QR pairing or device enrollment step. If Mop reports that it is waiting for
its identity, let Keychain synchronize and refresh the vault list.

Old device credentials and v4 vaults cannot be opened by this version. There is no
per-device revocation: all devices holding the account identity have the owner's
access. See [account identities](docs/ACCOUNT-IDENTITY.md).

## Read, write, run, and inject

```sh
mop write mop://personal/service/token              # hidden prompt or UTF-8 stdin
mop write --replace mop://personal/service/token
mop read mop://personal/service/token
mop read -n -o /private/tmp/token mop://personal/service/token
mop list --vault personal --json
mop delete mop://personal/service/token

TOKEN=mop://personal/service/token mop run -- your-command arg
mop run --env-file ./development.env -- your-command
printf '%s' '{{ mop://personal/service/token }}' | mop inject
mop inject -i template.conf -o generated.conf
```

Secrets are never accepted as positional arguments. `write --replace` requires an
existing field; ordinary `write` refuses to overwrite one. Reads add a newline
unless `-n` is set. File output is atomic, defaults to mode `0600`, and requires
`--force` to replace an existing regular file. `--file-mode` accepts octal modes.
References support `mop://vault/item/[section/]field`; percent-encode item, section, and field components.
`run` and `inject` can resolve references from multiple vaults in one command.

`run` reads literal dotenv files in order, overriding inherited variables. Values
starting with `mop://` resolve once; `$NAME` and `${NAME}` reference components
expand from the merged environment. `inject` expands `{{ mop://… }}` placeholders.
Fetched secrets are not recursively expanded. All references resolve before a
child starts or output is written. Repeated references are fetched once per command.
Commands and literal templates with no references need neither CloudKit nor Touch ID.

`run` masks exact nonempty fetched secret byte strings on stdout and stderr with
`[concealed by mop]`, including across stream chunks. `--no-masking` uses direct
execution and preserves terminal behavior. Masking cannot hide transformed secrets,
files or `/dev/tty` written by children, or deliberate bypasses. See
[examples](docs/EXAMPLES.md) for more command workflows.

## Automatic app updates and offline availability

The Mac, iPhone, and iPad apps automatically use the last verified encrypted
snapshot when disconnected. No offline toggle or separate Sync action is needed.
Local authentication is still required. Cached data is read-only; saving changes
requires iCloud. The status shows when cached data is in use.

CloudKit database change notifications trigger refreshes. Returning to the app,
reconnecting, and periodic checks while active also reconcile updates. Refreshes
wait until an open editor is finished. Background notifications can download
ciphertext without prompting; the next authenticated opening verifies it before
it becomes the offline snapshot. Push delivery and background execution are
scheduled by the operating system, so updates are not guaranteed to be immediate.

Only connection unavailability permits cached reads. Account, permission, trust,
ownership, and missing-vault errors remain errors. A device needs an initial
online authenticated opening before its vault is available offline.

### Command-line offline operation

Online commands fetch the current head before opening the vault. Writes succeed
only after server confirmation. No mutations are queued offline.

```sh
mop vault sync
mop vault status
mop read --offline mop://personal/service/token
mop run --offline -- your-command
mop vault export --offline --out-file /path/to/backup.mopfile
```

Only `read`, `list`, `item catalog`, `run`, `inject`, and encrypted `export` accept offline mode.
They use the last authenticated cache, require local authentication, and print its
fetch time to stderr. There is no implicit fallback after network errors. A sync
without authentication downloads ciphertext but does not promote it to the
verified offline snapshot. Offline use cannot detect remote ownership changes or an
account change not yet observed locally. An observed sign-out invalidates the
account binding; caches and defaults are isolated by account, container, environment,
and vault UUID.

Concurrent writes return exit code 11; rerun against current state. If a response
is lost, exit code 22 means the outcome is uncertain. Run `vault sync` online to
reconcile its recorded revision against committed ancestry before another write.
A live local writer holds a process lock. Interrupted staging is never exposed as
a committed vault and is never automatically replayed.

## Backups, v5 history, and recovery

Operational storage uses named CloudKit vaults.
References select named vaults. Import accepts only v5 backups:

```sh
mop vault import --file /path/to/existing.mopfile
mop vault export --out-file /path/to/backup.mopfile
```

An owned backup can be verified using the synchronized identity. Recovery-key
imports require established local trust or `--fingerprint` / `--revision` evidence
obtained independently. It preserves vault
identity and recovery relationships, refuses an existing destination head, and
never deletes or modifies the source file. Export creates a verified encrypted v5
backup; it does not include the recovery private key. Preserve the printed UUID.

```sh
mop vault conflicts
mop vault resolve --revision COMMITTED_REVISION_HASH
mop vault recover --recovery-file /offline/recovery.key \
  --fingerprint INDEPENDENT_VAULT_FINGERPRINT
```

History lists only committed v5 ancestry, never abandoned uploads, and stops at
the first v4 ancestor. Pre-v5 history cannot be restored. Restoration requires a
v5 revision decryptable by the current owner and keeps
the current vault name, recipients, and keys. Imported history starts at the imported snapshot;
file-vault backends and external `.history` directories are no longer supported.
Encrypted backup import/export remains supported. Immutable cloud revisions and
abandoned staged records are retained in this version and count toward quota.

Recovery restores vault access for the destination account after local authentication and trust verification.
For a deleted cloud zone, explicitly import an encrypted export. If the backup belongs to another account, use `vault import --file BACKUP --recovery-file KEY --fingerprint
FINGERPRINT` to verify the backup and wrap its keys for the account before publication.
The source backup remains unchanged.
Missing zones are never silently recreated by ordinary commands.

## Security limits and diagnostics

CloudKit's encryption supplements mop's encryption; secret confidentiality does
not depend on Advanced Data Protection being enabled. The service can observe
record sizes, update timing, and public membership metadata. It can delete data or
withhold changes. Local key pins and verified generation/digest watermarks reject
observed rollback and substitution. New devices establish owner trust through
the identity delivered by iCloud Keychain, but cannot infer global freshness
from the service alone.

Requested plaintext and unwrapped symmetric keys enter mop's process memory.
Compromised authorized code could request other secrets. Recovery remains an
alternative to the account identity. There is no guarantee of secure
erasure from Swift-managed memory or from historical copies.

Diagnostics go to stderr without secret values or arbitrary CloudKit error text.
Exit codes: 2 invalid arguments/offline mutation/legacy file options; 3 authentication;
4 missing secret; 5 duplicate/output exists; 6 Keychain; 7 I/O; 8 signing;
9 missing vault/default; 10 invalid vault; 11 conflict; 12 reserved;
13 identity not a vault member; 14 invalid identity/recovery; 15 unsafe file;
16 untrusted vault/rollback; 17 cloud unavailable; 18 cloud account;
19 quota; 20 throttling; 21 cloud permission; 22 uncertain commit;
126 launch failure; 127 executable missing. Child status is otherwise propagated.

```sh
mop completion bash
mop completion zsh
mop completion fish
```

See [CloudKit provisioning](docs/CLOUDKIT.md) and [validation](docs/VALIDATION.md)
before distributing a production build.

### iPhone and iPad application

The Mac, iPhone, and iPad interfaces share the `MopUI` SwiftUI library. Open
`Apple/Mop.xcodeproj` to build the mobile application; see [mobile application
instructions](docs/MOBILE.md) for simulator tests, TestFlight archives, and device
acceptance. The existing Mac packaging and CLI installation remain supported.
