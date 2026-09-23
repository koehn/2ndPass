# Security and key management

This guide describes the current CloudKit-backed CLI and native Mac app. See
[validation](VALIDATION.md) for executed tests and outstanding hardware/multi-Mac
acceptance, and the [security audit](security-audit/2026-09-23.md) for the reviewed
snapshot and subsequent remediation. Testing does not establish that all attacks
or deployment configurations have been independently audited.

## Protection boundaries

Mop protects secret confidentiality and integrity when encrypted cloud records or
backups are disclosed or replaced without the necessary keys and local trust.
CloudKit encryption supplements Mop's own encryption; Advanced Data Protection is
not required for that encryption boundary. The service can observe public device
metadata, vault IDs, record counts, sizes, update timing, and record reuse. It can
delete data or withhold changes. There is no padding or global freshness oracle.

The system assumes a trustworthy OS, signed application, local state, and
user-approved receiving programs. It cannot protect plaintext from a compromised
authorized process, malware running as the user, or an authorized child to which
secrets were explicitly supplied. Signing identifies the application, not the
shell program invoking it or the user's understanding of an authentication prompt.

There is no administrator/read-only enrollment distinction: every enrolled device
can access every record in that independent vault. A compromised authenticated
process can unwrap other record keys. The recovery private key is a full alternate
decryption capability; it does not require the original Mac, enclave, or biometrics.

## Storage and account binding

Operational storage is CloudKit. `--vault-file` and `MOP_VAULT_FILE` are rejected;
use explicit `vault import --file` to migrate a v3 file. Select an independent vault
by `--cloud-vault UUID`, then `MOP_CLOUD_VAULT`, then the account-scoped saved default.
The logical vault name inside `mop://personal/service/token` is a namespace within
that selected independent vault, not a separate CloudKit authorization boundary.

| Material | Location and handling |
|---|---|
| Encrypted records and manifests | Private CloudKit zone per independent vault UUID. Immutable encrypted records are referenced by revision manifests; a conditional head update publishes a revision. |
| Index and value keys | Random AES-256 keys, independently wrapped per device and recovery recipient. Only requested record keys are unwrapped during ordinary reads. |
| Device private-key representation | Application-specific Data Protection Keychain, service `mop.device-key.v2`. Opaque enclave blob; nonsynchronizing, authentication protected, this-device-only. |
| Device metadata | `~/.mop/device.json`: public key, display name, Keychain account UUID, and authentication policy. No private-key blob. |
| Local account binding, trust, snapshots, journals | Under `~/.mop/cloud/`, scoped by container, environment, account, and vault UUID. Never synchronize the state directory. Its integrity matters even though it contains no plaintext secrets or recovery private key. |
| Recovery credential | User-selected file containing `mop-recovery-v1:` plus an exportable P-256 private key in Base64. Base64 is not encryption. Move offline and keep separate from synchronized ciphertext/backups. |
| Encrypted export | User-selected `.mopfile` from `vault export`. Complete encrypted v3 snapshot, without the recovery private key. Retain independent trust evidence and the vault UUID. |

`--state-directory` or `MOP_STATE_DIRECTORY` overrides `~/.mop`. Preserve the device
metadata, Keychain item, and local trust across upgrades. A new directory does not
revoke an old device; deleting metadata does not delete its Keychain item.
An observed sign-out invalidates the local account binding. Online operations check
the current account; offline use cannot detect an account change not observed locally.

Snapshot documents are limited to 16 MiB. Local storage retains one downloaded and
one verified snapshot, each capped at 32 MiB including its JSON/Base64 envelope.
Atomic replacement can temporarily retain one additional envelope. Unverified
network records are assembled in bounded memory and do not create persistent blob
files. Incremental fetches reuse records embedded in the two snapshots. Opening a
cache removes obsolete hash-named `.blob` files from earlier versions while keeping
snapshots and commit journals. This is a per-vault bound, not an aggregate limit
across all selected accounts/vaults. Cloud history and abandoned server uploads are
not automatically pruned and continue to count toward the cloud quota.

## Authentication and signing

Every command that accesses secrets or authenticated metadata creates a fresh
`LAContext`, sets Touch ID reuse duration to zero, and evaluates owner
authentication. Additional prompting on that context is disabled after success.
The same authorization must satisfy the Keychain item and Secure Enclave key ACLs;
there is no software-key fallback or weaker retry. Opening a local device performs
a test wrap/unwrap to prove private-key access even for public device management.
Contexts are invalidated when the command closes or authentication fails.

The default key and item use `WhenUnlockedThisDeviceOnly` and user presence; the
enclave key also requires private-key usage. Touch ID or the login password may
authorize access. `--strict-biometrics` when creating a device uses
`biometryCurrentSet` and biometrics-only authentication with no password fallback.
Changing biometric enrollment then requires recovery. An existing non-strict key
cannot silently become strict; changing policy requires a new device key and
revocation of the old one. Editing metadata cannot weaken the OS-enforced ACLs.

Operational access requires the provisioned signed bundle. Validation requires a
narrow application-specific Keychain access group, hardened runtime, a matching
bundle, and an embedded provisioning profile, and rejects the supported debugging
and library-validation exceptions. The CLI helper also validates the enclosing
bundle seal. Keep the application identifier, team, and CloudKit container stable.
Do not extract the executable from the app bundle for installation.

The opaque enclave blob is protected by the Keychain access group. It is not
intrinsically app-bound once extracted by compromised authorized code; hardware
and its ACL still restrict its use. Loss of the Keychain item or enclave state
requires recovery even if public device metadata remains.

Help, completions, ciphertext sync/status/history, public enrollment-request
listing, and commands with no secret references do not unlock secret values.
Public enrollment metadata is not authenticated identity evidence.

## Encryption and integrity

An AES-256-GCM index key encrypts canonical reference names and random record IDs.
Every secret has an independent random AES-256-GCM value key. CryptoKit HPKE
`P256_SHA256_AES_GCM_256` wraps the index key and each value key separately for each
enrolled device and one offline recovery recipient.

- HPKE context binds the v3 domain, vault UUID, recipient role/fingerprint, and
  purpose (`index` or `record:UUID`). Index and record wraps cannot be interchanged.
- Index associated data authenticates the complete header and a SHA-256 digest of
  the canonical encrypted record table, including wrapped keys. It binds table
  membership and bytes without decrypting all values.
- Value associated data binds vault UUID and record ID. AES-GCM uses fresh random
  nonces. Replacement uses a fresh record ID/key; deletion does not decrypt old values.
- Canonical references must map one-to-one to the record table. Recipient lists,
  public keys, wrap sizes, generation, and document size are validated. Legacy
  document/device formats are rejected.

Listing decrypts only the index. Enrollment unwraps and rewraps record keys without
opening values. Revocation and history restoration process values individually.
The index key is an integrity authority: its holder can forge a header/index and
insert chosen records, though it cannot alone decrypt existing independent record
keys. There are no per-user signatures or enclave-enforced per-field allowlists.

## Trust and rollback

Public-key encryption alone does not authenticate a vault. Anyone with public
recipient keys can encrypt an attacker-chosen index key for those recipients.
Mop therefore verifies an independent local pin before accepting decrypted data.

| Evidence | Meaning |
|---|---|
| Device fingerprint | SHA-256 of the device P-256 public key. Compare independently before approving enrollment; it does not attest hardware or the display name. |
| Vault fingerprint | SHA-256 commitment to the v1 trust domain, vault UUID, and raw index key. Stable across writes/enrollment; changes on key rotation. |
| Revision hash | SHA-256 of exact serialized encrypted snapshot bytes. Changes on every revision and proves only those exact bytes. |

Cloud pins are local to the account/container/environment/vault binding. Ordinary
opens require the active fingerprint. Initialization establishes trust in a key
created locally; existing data requires an established pin or independently
obtained fingerprint/revision evidence. Explicit history restoration can use a
previous pin under its other current-authorization checks. Do not manufacture
approval evidence by hashing only a suspect cloud record or backup.

After authentication, a generation/digest watermark rejects lower generations and
a different revision at the same generation. Downloads alone do not advance it or
replace the verified offline snapshot. A new Mac cannot infer global freshness
from the cloud alone; a device that has not observed a newer revision may still
accept an older one. Local state modification/deletion can undermine these pins
and watermarks; they are not hardware-sealed monotonic counters.

## Enrollment, revocation, and recovery

Initialize and retain the printed vault UUID and fingerprint independently:

```sh
mop vault init --recovery-file /offline/mop-recovery.key --name 'First Mac'
mop vault list
mop vault use VAULT_UUID
```

Recovery material is written before cloud publication and retained if a later
step fails. Initialization prints the UUID to stderr before publication so an
interrupted creation can be reconciled. Do not discard recovery material or
blindly repeat initialization after an uncertain outcome.

On a new Mac, select the vault and publish its public request:

```sh
mop vault use VAULT_UUID
mop device request --name 'Second Mac'
```

On an enrolled Mac, independently compare the complete device fingerprint before
approval. Request names and fingerprints downloaded from the service are untrusted:

```sh
mop device requests
mop device add REQUEST_ID --fingerprint VERIFIED_DEVICE_FINGERPRINT
mop vault fingerprint
```

On the new Mac, independently compare and pin the vault fingerprint:

```sh
mop vault trust --fingerprint VERIFIED_VAULT_FINGERPRINT
```

Enrollment does not rotate keys. Removal rotates the index key and every current
value key, and prints a new vault fingerprint for the remaining Macs to verify and
pin independently. The issuing device cannot remove itself:

```sh
mop device list
mop device remove DEVICE_FINGERPRINT
```

Removed recipients can still decrypt old ciphertext, history, backups, and offline
caches, and retain values already learned. Rotate actual passwords/API tokens at
the provider if a device may have exposed them; vault-key rotation does not change
those credentials. There is no remote secure wipe.

Recovery enrolls the new Mac after local authentication and trust verification:

```sh
mop vault recover --recovery-file /offline/mop-recovery.key \
  --fingerprint VERIFIED_VAULT_FINGERPRINT --name 'Replacement Mac'
```

Recovery does not automatically remove lost devices or rotate the vault key.
Revoke them afterward. There is no recovery-key replacement command; if that
credential is compromised, create a new vault with a new recovery key and move
current secrets explicitly. Losing all device keys and recovery material makes
the data unrecoverable. Losing independent trust evidence is a separate problem;
successful recovery decryption does not bypass trust checks.

## Synchronization, offline reads, and backups

Online commands fetch the current head before opening a session. Writers stage
immutable blobs/manifests and publish with a server-conditional head update.
A stale writer fails with conflict exit code 11. A live local writer holds a process
lease; interrupted/uncertain writes are recorded in a journal and reconciled against
committed ancestry by online `vault sync`. Exit code 22 requires reconciliation
before another write. Interrupted staging is not replayed or exposed as a committed
vault. Missing cloud zones are never silently recreated by normal commands.

Explicit `--offline` reads use only the last authenticated snapshot, still require
local authentication, and report its fetch time. There is no implicit fallback
from a network failure, no offline mutation queue, and no way for offline use to
observe later revocation. `vault sync` alone downloads ciphertext without promoting
it to the authenticated snapshot.

```sh
mop vault sync
mop vault status
mop vault export --offline --out-file /path/to/backup.mopfile
mop vault import --file /path/to/backup.mopfile --fingerprint VERIFIED_VAULT_FINGERPRINT
mop vault conflicts
mop vault resolve --revision COMMITTED_REVISION_HASH
```

Import verifies established source-path trust or independent evidence, preserves
vault identity/recovery relationships, refuses an existing destination head, and
leaves the source untouched. A replacement Mac can add `--recovery-file` to import
and enroll before publication. Imports do not upload legacy `.history` directories.
Restoration selects only committed ancestry and retains current recipients/keys,
re-encrypting historical values for them. It cannot reinstate a revoked device.
Local trust completion and server publication are separate transactions; preserve
trusted evidence and reconcile if publication succeeds but local completion fails.

`VaultDisk`/`FileSecretStore` remain legacy adapter APIs for tests and migration.
Their path-scoped pins, filesystem coordination, `.history` files, and lack of
same-key generation watermarks do not describe the operational CloudKit backend.

## Plaintext, files, and the native app

Private files use owner-only permissions and strip inherited ACL grants before
contents are written. Private reads check ownership, mode, type, and ACLs. File
output is atomic, exclusive by default, rejects unsafe destinations, and cannot
target the local state directory. `--force` permits replacement of a regular output
file; explicit `--file-mode` controls exported plaintext permissions. Shell
redirection can truncate files before Mop starts and is outside these checks.

Requested plaintext and unwrapped symmetric keys enter process memory. Swift does
not guarantee complete zeroization. `run` passes resolved secrets to the selected
child environment and closes authentication first. Exact nonempty fetched byte
strings are masked on stdout/stderr, including across chunks; transformed output,
files, `/dev/tty`, or deliberately malicious children can bypass masking. No shell
is implicitly invoked, and reference expansion does not recursively expand secrets.

The native app invokes the bundled CLI for fresh authentication per operation;
values travel through stdin/stdout pipes, not arguments or temporary files. Secret
copies use a device-local pasteboard entry, a cooperative confidential-content
marker, and a 30-second expiry. Revealed text cannot be copied through native text
selection; use Copy value. Clearing checks the pasteboard change count to avoid
erasing another application's newer content. Clipboard readers can still capture
an intentionally copied value; cooperative markers are not access controls.

App deactivation immediately hides sensitive content from display and accessibility
and conceals values. If authentication returns focus before completion, its result
can be displayed. A command completing while inactive leaves the app locked and
discards visible results. Explicit lock, session deactivation, and sleep also clear
owned clipboard contents. Ordinary app switching allows pasting until expiration.
Submitted mutations can still complete after locking; reconcile uncertain results
with Sync. The app does not persist plaintext in preferences or logs.
