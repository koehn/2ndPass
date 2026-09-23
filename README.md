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

mop is a macOS command-line secret manager with CloudKit synchronization and
Secure Enclave-protected access. It supplies credentials to commands and templates
using references such as `mop://personal/service/token`.

**CloudKit implementation: signed two-Mac and production acceptance are still
required before release.** See [validation](docs/VALIDATION.md).

Requires macOS 15+, a Secure Enclave, a logged-in macOS user, an Apple Account
with iCloud access, and a provisioned signed application. There is no software-key
or unsigned-build fallback for secret access.

## Storage and authentication

mop encrypts the index and each secret locally using the existing `mop-vault-v3`
format. Each secret has an independent AES-256-GCM key. HPKE wraps the index and
secret keys separately for every enrolled Mac and for an offline recovery key.
CloudKit stores individual immutable encrypted records and revision manifests;
a conditional head update publishes a complete revision. Unchanged secret records
are reused. Concurrent writers fail explicitly rather than overwrite changes.

Every secret command authenticates afresh with Touch ID or the system password.
`--strict-biometrics` on initial device creation requires the current Touch ID
set with no password fallback. Changing biometric enrollment then requires
recovery. The Secure Enclave key and its Keychain item enforce the policy;
there is no synchronizing private key or app-only authentication gate.

An independent CloudKit vault has its own UUID, zone, enrollment list, recovery
credential, and trust fingerprint. Logical names such as `personal` in a
`mop://personal/service/token` reference remain namespaces *inside* that vault.
Multiple independent vaults are supported. Cross-account sharing is not yet
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

1. Register an explicit macOS App ID (default `net.koehn.mop`). Enable iCloud with
   CloudKit and the application-specific Keychain access group.
2. Associate the container `iCloud.<bundle identifier>` with the App ID.
3. Generate a provisioning profile authorizing that container and the selected
   CloudKit environment. Create the schema described in [CloudKit setup](docs/CLOUDKIT.md).
4. Package the application:

```sh
export MOP_SIGN_IDENTITY='Your Apple signing identity'
export MOP_PROVISION_PROFILE='/path/to/profile.provisionprofile'
export MOP_BUNDLE_ID='net.koehn.mop'
export MOP_CLOUD_ENVIRONMENT='Development' # Production for release builds
scripts/package.sh
scripts/install.sh dist/Mop.app
mop device identity
```

Packaging defaults to `Production` and rejects profiles without the matching
CloudKit environment/container. It emits only the narrow Keychain and CloudKit
entitlements, without debugging exceptions. Moving the executable out of its app
bundle breaks access; the installer uses a symlink to the bundled executable.
Developer profiles/environments are distinct from production data.

## Create and select a vault

```sh
mop vault init --recovery-file "$HOME/mop-recovery.key" --name 'First Mac'
mop vault list
mop vault use VAULT_UUID
```

Initialization prints the vault UUID, device fingerprint, and vault fingerprint.
Move the recovery file offline and retain the vault fingerprint with it. The
recovery credential is a full alternative decryption capability: never put it
in CloudKit or keep it next to a synchronized backup. A failed initialization
retains any recovery file already written.

The first successfully created/imported vault becomes the local account default.
Choose a vault with `--cloud-vault UUID`, then `MOP_CLOUD_VAULT`, then the saved
default, in that order. A missing default is an error, not an arbitrary selection.
A new Mac can run `vault list`, then `vault use UUID` before enrollment.

Local metadata defaults to `~/.mop`, overridden by `--state-directory` or
`MOP_STATE_DIRECTORY`. **Never synchronize this directory.** It contains public
device metadata, account-scoped ciphertext caches, commit journals, and local
trust pins. The private enclave key blob lives only in the application's
nonsynchronizing Data Protection Keychain. Keep both metadata and the Keychain
item across upgrades. Secret output cannot target the state directory.

## Enroll another Mac

Install the same provisioned application on both Macs and sign into the same
Apple Account. On the new Mac:

```sh
mop vault list
mop vault use VAULT_UUID
mop device request --name 'Second Mac'
```

On an enrolled Mac:

```sh
mop device requests
mop device add REQUEST_ID --fingerprint FINGERPRINT_FROM_NEW_MAC
mop vault fingerprint
```

Compare the full device fingerprint using an independent trusted channel. The
request list is untrusted public metadata, not evidence of identity. Then, on the
new Mac, compare and pin the vault fingerprint from the trusted Mac:

```sh
mop vault trust --fingerprint VAULT_FINGERPRINT_FROM_TRUSTED_MAC
```

Requests remain available for auditing/retry; approval does not delete them.
A pending request never grants access by itself.

```sh
mop device list
mop device remove DEVICE_FINGERPRINT
```

Removal rotates the index key and every secret key. Verify and pin the newly
printed vault fingerprint on remaining Macs. Old ciphertext, backups, and offline
caches remain decryptable by their former recipients. Remote removal cannot erase
secrets already learned. You cannot remove the device executing the command.

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
References support `mop://vault/item/[section/]field`; percent-encode components.

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

## Offline operation and synchronization

Online commands fetch the current head before opening the vault. Writes succeed
only after server confirmation. No mutations are queued offline.

```sh
mop vault sync
mop vault status
mop read --offline mop://personal/service/token
mop run --offline -- your-command
mop vault export --offline --out-file /path/to/backup.mopfile
```

Only `read`, `list`, `run`, `inject`, and encrypted `export` accept offline mode.
They use the last authenticated cache, require local authentication, and print its
fetch time to stderr. There is no implicit fallback after network errors. A sync
without authentication downloads ciphertext but does not promote it to the
verified offline snapshot. Offline use cannot detect remote revocation or an
account change not yet observed locally. An observed sign-out invalidates the
account binding; caches and defaults are isolated by account, container, environment,
and vault UUID.

Concurrent writes return exit code 11; rerun against current state. If a response
is lost, exit code 22 means the outcome is uncertain. Run `vault sync` online to
reconcile its recorded revision against committed ancestry before another write.
A live local writer holds a process lock. Interrupted staging is never exposed as
a committed vault and is never automatically replayed.

## Migration, backups, history, and recovery

Operational `--vault-file` and `MOP_VAULT_FILE` have been removed. Unset the old
environment variable, retain your device state, and explicitly import:

```sh
unset MOP_VAULT_FILE
mop vault import --file /path/to/existing.mopfile
mop vault export --out-file /path/to/backup.mopfile
```

Import requires the source's established local trust, or `--fingerprint` /
`--revision` evidence obtained independently. It accepts v3 only, preserves vault
identity and recovery relationships, refuses an existing destination head, and
never deletes or modifies the source file. Export creates a verified encrypted v3
backup; it does not include the recovery private key. Preserve the printed UUID.

```sh
mop vault conflicts
mop vault resolve --revision COMMITTED_REVISION_HASH
mop vault recover --recovery-file /offline/recovery.key --name 'Replacement Mac' \
  --fingerprint INDEPENDENT_VAULT_FINGERPRINT
```

History lists only committed ancestry, never abandoned uploads. Restoration keeps
current recipients and keys. Imported history starts at the imported snapshot;
external `.history` directories are not uploaded. Immutable cloud revisions and
abandoned staged records are retained in this version and count toward quota.

Recovery enrolls the current Mac after local authentication and trust verification.
For a deleted cloud zone, explicitly import an encrypted export. If no enrolled
device remains, use `vault import --file BACKUP --recovery-file KEY --fingerprint
FINGERPRINT` to verify the backup and enroll the new Mac before publication.
The source backup remains unchanged.
Missing zones are never silently recreated by ordinary commands.

## Security limits and diagnostics

CloudKit's encryption supplements mop's encryption; secret confidentiality does
not depend on Advanced Data Protection being enabled. The service can observe
record sizes, update timing, and public device metadata. It can delete data or
withhold changes. Local key pins and verified generation/digest watermarks reject
observed rollback and substitution, but a new device needs independent trust
and cannot infer global freshness from the service alone.

Requested plaintext and unwrapped symmetric keys enter mop's process memory.
Compromised authorized code could request other secrets. Recovery remains an
alternative to the hardware authentication path. There is no guarantee of secure
erasure from Swift-managed memory or from historical copies.

Diagnostics go to stderr without secret values or arbitrary CloudKit error text.
Exit codes: 2 invalid arguments/offline mutation/legacy file options; 3 authentication;
4 missing secret; 5 duplicate/output exists; 6 Keychain; 7 I/O; 8 signing;
9 missing vault/default; 10 invalid vault; 11 conflict; 12 unavailable enclave;
13 unenrolled device; 14 invalid device/recovery; 15 unsafe file;
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
