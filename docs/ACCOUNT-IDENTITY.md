# Account identities and vault membership

Mop uses one identity per CloudKit container, environment, and Apple Account.
The identity has separate P-256 encryption and signing private keys, stored as one
64-byte synchronizable Data Protection Keychain item. The item is available while
the device is unlocked and uses the application's provisioned access group. Mac
and mobile must use the same access group, container, and environment. Mop performs
local user authentication before retrieving the identity; these synchronizable
keys are deliberately software keys, not non-exportable Secure Enclave keys.

## Setup and synchronization

A private CloudKit identity zone contains a public, self-signed identity anchor.
It selects one immutable Keychain item by random UUID. The zone is excluded from
vault discovery. Keys are saved to Keychain before conditionally creating the
anchor. Competing devices use the winning anchor; they do not overwrite a key or
replace an identity when the winning Keychain item has not arrived. Lost cloud
acknowledgements are reconciled by reading the anchor, never by blindly repeating
the mutation. Orphan losing candidates may remain in Keychain (64 bytes of key
material each, plus system metadata); they grant no vault membership.

The key namespace and signed anchor bind the container, environment and opaque
CloudKit account ID. A previously observed anchor cannot silently change. An
absent anchor for existing v5 vaults is a recovery error, not permission to create
a different owner. Account changes invalidate sessions. Private identity material
never enters CloudKit, application preferences, logs, or exported vault backups.

Keychain delivery is asynchronous. New devices show a waiting error if the anchor
exists but its private keys are unavailable. Enable iCloud Passwords & Keychain,
wait for synchronization, and refresh the vault list. Mop cannot reliably infer
that sync has completed merely because a local Keychain insert succeeded. Trust
or identity failures pause automatic authentication across input and foreground
transitions. Explicit refresh retries; ordinary cancellation still permits a new
attempt on the next interaction.

## Vault format and membership

New vaults use `mop-vault-v5` from their first revision. Each has exactly one owner
member and one offline recovery recipient. The owner signs a membership statement
binding the vault UUID, owner encryption/signing public keys, role, and vault-key
fingerprint. Every revision additionally signs the complete header, sealed index,
and digest of its record table. The recovery credential may sign authorized
recovery operations. AES-GCM and per-recipient HPKE continue to protect the index
and individual values. CloudKit commits remain conditional and journaled.

Owner/editor/viewer role names exist in the model, but this version accepts only
one owner. Adding members, changing roles, CloudKit shared databases, cross-account
invitations, and an owner-authority transition protocol are not implemented. They
must not be approximated by inserting unsigned recipients or trusting cloud-only
public keys. Apple Account membership grants all that account's devices access;
there is no independent per-device revocation in v5.

Fresh devices authenticate a v5 vault against their Keychain-delivered identity,
verify its signed key fingerprint and encrypted contents, then save local trust.
The existing watermark and committed ancestry checks remain in force. Previously
unseen devices cannot detect every server replay of valid historical state; this
is not a global freshness or server-availability guarantee.

## Supported formats and history

Only v5 vaults and backups are accepted. Legacy device credentials are never
opened, and there is no pairing, enrollment, device revocation, or conversion
path. Older cloud objects and local files are left untouched; an older compatible
client is needed to access them separately.

Existing v5 vaults created by an earlier conversion remain supported. History
listing stops before the first v4 ancestor, and pre-v5 revisions cannot be
restored. Restore accepts only committed v5 revisions decryptable by the current
owner. Historical objects are not automatically deleted. Import begins a new
history root at the verified v5 snapshot.

## Recovery and backups

Recovery credentials remain independently capable of decrypting the vault and
its backups. Recovery/import verifies independent fingerprint or revision evidence
and can rewrap a vault to the destination account's identity, rotating all keys
when ownership changes. Exported backups contain no account private keys and no
recovery private key. Preserve the current vault fingerprint with recovery plans.

An existing account identity that is missing from Keychain is not silently reset
by vault recovery. Restore that identity through iCloud Keychain recovery, or use
a backup and its recovery credential to import into another account with a usable
Mop identity. Recovery of one vault is not an implicit reset of all account keys.
Cross-account sharing and collaborative account recovery require further design.

## Validation and physical acceptance

Unit/integration tests use software test keys and fake CloudKit/Keychain storage.
They exercise signed membership, old-format rejection, recovery key rotation, concurrent
identity selection, delayed Keychain delivery, dropped acknowledgements, account
changes, cancellation, and a new device opening multiple owned vaults. Simulator
UI fixtures remain Debug-only; production authentication is not bypassed.

Before release, test signed Mac and iPhone/iPad builds with matching Keychain access
groups: create multiple v5 vaults, wait for Keychain sync, open
them on a fresh device, edit from each device, lock/relaunch,
disable/re-enable Keychain sync, and verify backup recovery. Also test different
Apple Accounts and Development/Production isolation. Simulator tests cannot prove
real iCloud Keychain delivery or Face ID/Touch ID behavior.

Apple references: [synchronizable items](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
and [secure Keychain syncing](https://support.apple.com/guide/security/sec0a319b35f/web).
