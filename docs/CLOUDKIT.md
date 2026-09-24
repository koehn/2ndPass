# CloudKit provisioning and acceptance

## Container and schema

Use the native private database of `iCloud.<bundle identifier>`. Enable that exact
container in the App ID and provisioning profile. Set `MOP_CLOUD_ENVIRONMENT` to
`Development` while testing and to `Production` when packaging a release. Both
builds must carry matching environment entitlements; runtime configuration cannot
redirect a signed binary to another container/environment.

In CloudKit Console's **development** environment create these record types:

| Record type | Field | Type | Record IDs |
|---|---|---|---|
| MopHead | payload | Asset | `head` |
| MopBlob | payload | Asset | `s-<ciphertext SHA256>`, `m-<revision SHA256>`, or `account-identity-v1` |

No query indexes are required: v5 fetches records by ID. Vault data uses custom
`mop-<UUID>` zones. The reserved identity zone
`mop-7C6F7075-7365-4273-8964-656E74697479` contains the public identity anchor and is
excluded from vault discovery. No public database or CloudKit shares are used.
The obsolete MopRequest type may remain on the server but is never read or written.
Use CloudKit Console to deploy the tested schema to production before release.
Schema deployment is an administrative action, not an application startup task.
The implementation must never use `CKSyncEngine` or silently recreate deleted
zones during normal reads/writes.

The `payload` asset already contains mop ciphertext, or public metadata for
requests. A manifest contains the existing authenticated header and encrypted
index plus a map from secret record UUID to ciphertext hash. Reconstructing the
canonical signed v5 document authenticates the complete record table. A manifest's ID is
the hash of that complete document, not the hash of the manifest bytes.

Only the small head record is mutable. Its save uses the fetched record's system
fields and `.ifServerRecordUnchanged`. Immutable blobs are fetched and checked
before reuse. Any collision with different bytes fails closed. Interrupted staged
uploads are retained but are not reachable through committed history.

## Signed acceptance procedure (required before release)

Use a dedicated test Apple Account and disposable v5 data in Development. Sign
Mac/iPhone/iPad builds with matching access groups, container, and environment.
Isolated local state directories do not isolate the synchronized account identity.
Keep recovery credentials and independently recorded fingerprints separate.

1. On A run `mop vault init personal --recovery-file /offline/personal.key`,
   write two secrets, export a v5 backup, and verify values. Inspect CloudKit:
   no plaintext values, item paths, account private keys, or recovery keys.
2. Enable iCloud Passwords & Keychain on B. Wait for identity delivery, then
   discover and read the owned vault with local authentication. There is no
   enrollment/approval step. Missing synchronized keys must cause a waiting error.
3. Edit on A and refresh/read on B. Unchanged encrypted records are reused.
   Concurrent writes must yield a single conditional-head winner and a conflict
   for a stale writer, without silent overwrites.
4. Verify explicit CLI `--offline` reads and refusal of offline writes. Native
   apps may automatically fall back only on connectivity failures. Reconnect and
   verify refresh without losing a draft or exposing an uncommitted write.
5. Restore a committed v5 revision. Confirm current name, membership, and keys
   remain authoritative. Pre-v5 history is excluded and cannot be restored.
6. Interrupt staging and head submission. Sync must reconcile uncertain outcomes
   without replaying a mutation. Repeat during recovery to a new owner with a
   usable identity, verifying rotation and independent trust evidence.
7. Change/sign out of accounts and test Development/Production separation.
   Observe missing-anchor and delayed-key failures, rather than identity reset.
   Test deleted zones, throttling/quota failures, and backup import into an absent
   head. Ordinary commands must not recreate a missing zone.
8. Perform the physical authentication, signing, lifecycle, clipboard, recovery,
   and accessibility checks in [VALIDATION.md](VALIDATION.md). Device revocation
   is not a v5 capability; do not claim it was tested.

After Development acceptance, promote the schema and use a new disposable
Production vault for signed initialize/write/read/export/recovery checks. Record
build/signing identity, OS versions, environment, test UUIDs, and outcomes.
Do not publish until the required acceptance passes.

## Failure and recovery behavior

Network operations have request/resource deadlines. A failure before publishing
clears the local journal; a possibly submitted head save retains it. A later sync
walks the committed chain to distinguish success from an abandoned mutation.
If the head is absent it records `head-missing`, clears the interrupted journal,
and still reports a missing vault; only explicit creation/import can recreate it.
Initialization prints its target UUID before publication so this can be reconciled
with `vault sync --vault UUID` even if no default was saved.
Authentication and explicit trust are still required before reading staged or
cached contents. A locally generated pending fingerprint permits finishing our
own interrupted initialization/key rotation, never trusting a fingerprint fetched
from CloudKit.

Exports are encrypted v5 documents and can be imported only into an absent head.
An import is an explicit creation operation; it may recreate a previously deleted
zone after verification. Import does not bring along older external history files.
There is no automatic history/staging garbage collector yet. Delete disposable
zones in CloudKit Console after acceptance and remove only their isolated local
fixtures. Never delete the synchronized account identity as vault-test cleanup;
that deletion propagates to other devices.

## Named v5 vaults

New manifests use `mop-cloud-manifest-v2`, containing `mop-vault-v5` headers
with a required name. The encrypted index maps relative `item/[section/]field`
paths to record IDs. UUID-based zones and record encryption remain unchanged;
the existing v3 cryptographic domain strings are retained because their key-wrap
and value-encryption protocols are unchanged. Header names are included in index
associated data, so changing an unauthenticated discovery name cannot authorize
access. Rename publishes a normal revision without uploading new secret blobs.
Restoring supported v5 history retains the current name and authorization.
Traversal stops at a v4 ancestor without downloading its secret records. Older
backups and vault heads are rejected, with no conversion or automatic deletion.

Discovery reads committed heads/manifests without decrypting secrets. Legacy
manifests are reported but not opened. Creation/import/rename check current name
availability; separate-zone races can still create duplicates and resolution then
fails explicitly. UUID selection remains available to repair names. No global
name registry or cross-zone transaction is introduced.

## Automatic application refresh

Native apps register for silent remote notifications and save the private database
subscription `mop-private-database-v1`. Xcode builds include the platform-specific
APNs entitlement and mobile `remote-notification` background mode. macOS script
packages copy the APNs environment from the provisioning profile when present;
use a profile containing `com.apple.developer.aps-environment` for push delivery.
Foreground and periodic refresh still work without push registration.

Notifications are hints; authenticated reads always validate the fetched revision.
Background downloads store ciphertext only. Reconnection and foregrounding also
refresh, and active sessions reconcile every minute to recover missed pushes.
Unsaved editors defer automatic refresh. Previously verified snapshots remain
readable during transport outages, without changing the authentication session.

Signed-device acceptance: open a vault online on both devices, change an item on
A, and confirm B updates without manual refresh. Repeat while B is backgrounded,
then foreground it. Disconnect B and relaunch: authenticate and read its cached
secret, verify mutations require a connection, then reconnect and confirm updates.
Repeat with an open edit on B (no draft loss) and an account change (no old cache
fallback). APNs delivery requires signed physical-device testing; unit tests and
unsigned simulator builds do not establish delivery or background scheduling.
