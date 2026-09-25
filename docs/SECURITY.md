# Security and key management

For an introduction without assumed cryptography or Apple platform knowledge,
read [how Mop protects your secrets](SECURITY-EXPLAINER.md). This document is the
technical reference for the current implementation.

Mop accepts only `mop-vault-v5` vaults and backups. It does not open legacy device
credentials, enroll or pair devices, convert older vaults, or restore pre-v5
history. Existing server objects and old local credentials are left untouched.
Use an older compatible client separately if you need access to older data.

[Account identities](ACCOUNT-IDENTITY.md) specifies the identity and membership
model. [Validation](VALIDATION.md) distinguishes automated tests from required
signed-device acceptance. Dated reports under `security-audit/` describe their
reviewed snapshots, not a certification of the current implementation.

## Protection boundaries

Mop protects confidentiality and integrity of encrypted vault contents against
exposure or substitution of cloud records without the necessary keys. CloudKit
sees vault names, IDs, public membership and recipient keys, sizes, record counts,
update timing, and record reuse. It can withhold or delete data. There is no
padding, service-availability guarantee, or global freshness oracle.

The system assumes a trustworthy OS and signed application. An authorized process
can access keys and plaintext in memory. It cannot protect against compromised
Mop code, an attacker with the account's private identity, or an authorized child
program receiving a secret. Output masking hides exact byte matches only; it is
not a containment boundary. A recovery credential independently grants full
vault decryption capability.

## Account keys and local authentication

An account identity contains separate P-256 encryption and signing private keys.
Their 64-byte representation is stored in an application-specific, synchronizable
Data Protection Keychain item with `WhenUnlocked` accessibility. Keys intentionally
synchronize through iCloud Keychain; they are exportable software keys, not
non-exportable Secure Enclave private keys. Mac and mobile builds require matching
Keychain access groups, CloudKit container, and environment.

A self-signed public CloudKit anchor selects an immutable Keychain item. Its scope
binds container, environment, and account. Concurrent initialization uses a
conditional create; losing candidates do not replace the winning identity.
Missing synchronized material produces a waiting/recovery error, never silent
identity replacement. Previously observed anchors cannot silently change.

Mop performs local user authentication before loading the identity. CLI commands
use a fresh context with biometric reuse disabled and close it on completion.
Native apps reuse authorization until explicit lock, account/protected-data loss,
or the inactivity deadline (1–60 minutes, default 5). Temporary backgrounding
conceals the UI but may retain the session until that deadline. Pending native
operations have generation/cancellation checks to prevent late results reopening
a locked interface; a submitted cloud mutation may still complete.

Authentication uses the system device-owner policy, allowing biometrics or the
system password/passcode. There is no biometric-only option or saved local
authentication policy. Older `account-authentication.json` files are ignored.
This authentication is enforced by the application, not a per-use Keychain ACL.
Changing enrolled biometrics does not invalidate the synchronized account keys.

There is one owner per vault. Every device receiving the account identity can
access its owned vaults. Independent per-device revocation, collaborative roles,
cross-account sharing, and account-key rotation are not implemented. Recovery can
rewrap a vault to another usable account identity and rotates all vault keys when
ownership changes. It does not reset a missing identity for the original account.

## Encryption, signatures, and trust

Each vault has a random AES-256-GCM index key and independent random AES-256-GCM
value keys. CryptoKit HPKE `P256_SHA256_AES_GCM_256` wraps each key for the owner
and one recovery recipient. Context binds vault UUID, recipient role/fingerprint,
and purpose (`index` or `record:UUID`). The existing v3 cryptographic domain strings
remain because the wrapping and value-encryption constructions have not changed.

Index associated data binds the header and digest of the complete encrypted record
table, including key wraps. Value associated data binds vault UUID and record ID.
Replacement values get fresh IDs and keys. The owner signs membership, including
the vault-key fingerprint. Each v5 revision signs its header, sealed index, and
record-table digest; the validated owner or recovery key must sign it.

The encrypted index contains references and visible item fields. Password, OTP,
and concealed values have separate encrypted records; listing does not decrypt
them. OTP reads return a code, while an edit can access the stored seed. Converting
a visible field to concealed removes its index copy from the new revision, not
from historical encrypted copies. Plaintext and some framework-managed key copies
exist in memory; wiping owned buffers is not a guarantee of total memory erasure.

A fresh device verifies the vault against its Keychain-delivered identity, signed
membership fingerprint, and authenticated contents before recording local trust.
Recovery requires an existing local pin or independent fingerprint/revision
evidence. Cloud discovery alone never establishes trust. `vault trust` verifies
independent evidence using the account identity. Local state is scoped by
container, environment, account, and vault UUID; never synchronize it.

Verified generation/digest watermarks reject observed rollback and same-generation
substitution. A fresh device cannot detect every valid historical replay. Offline
reads cannot discover unseen account changes or remote changes after caching.

## Cloud commits, caches, and history

Immutable encrypted records and revision manifests are uploaded before a
conditional head update publishes them. A process writer lease prevents concurrent
local reconciliation; a journal records uncertain publication. Run `vault sync`
after an uncertain result. Mutations are not automatically replayed.

Downloaded snapshots remain distinct from cryptographically verified snapshots.
Only verified snapshots support offline access. The CLI requires `--offline`;
native apps fall back only for connectivity unavailability, not account,
permission, integrity, or missing-vault failures. Online writes remain mandatory.

Documents are capped at 16 MiB. The local downloaded and verified snapshot
envelopes are each capped at 32 MiB; atomic replacement temporarily needs another
envelope. Record downloads do not accumulate persistent per-record blob files.
These are per-vault bounds, not a global disk budget.

History lists only committed v5 ancestors and stops before a v4 ancestor.
Restoration requires a supported revision decryptable by the current owner and
reseals values under current authorization. Pre-v5 history is neither listed nor
restored. After an ownership transfer, revisions encrypted solely to the former
owner are also unavailable to ordinary restoration. An imported backup starts a
new accessible history root. Old cloud objects and abandoned uploads remain until
explicit vault deletion; there is no automatic pruning.

## Files, clipboard, signing, and recovery

Local state uses private permissions, ACL checks, symlink/type checks, and atomic
writes. Mobile state additionally uses complete Data Protection and backup
exclusion. Output files default to mode 0600, refuse replacement unless requested,
and cannot target the state directory. Recovery files contain an unencrypted
Base64 private key: keep them offline, separate from encrypted backups and
independent fingerprint evidence. Exports contain neither account private keys
nor the recovery private key. Only v5 backups can be imported.

Concealed clipboard copies are device-local, expire after 30 seconds, and clear on
explicit lock if Mop still owns the clipboard. iOS enforces the expiration while
suspended; macOS clearing depends on the app running. Visible values need not
expire. Clipboard-manager confidentiality markers are cooperative, not ACLs.

macOS requires a provisioned signed bundle, narrow access group, hardened runtime,
and enclosing bundle validation, rejecting supported debugging/injection
exceptions. Installation preserves the entire bundle and identity. iOS relies on
platform signing/entitlement enforcement and validates its configured access group.
Simulator UI fixtures are Debug-only and excluded from device/Release builds.
`mop device identity` remains a noninteractive signing diagnostic only.

Deletion removes the complete selected cloud zone, including unsupported history,
and clears that vault's local state after verifying remote absence. It does not
remove the shared account identity, backups, or another device's cached data.
Never delete a synchronized account Keychain item as disposable-vault cleanup:
that deletion can propagate to every device.
