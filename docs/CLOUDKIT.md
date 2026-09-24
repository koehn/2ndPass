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
| MopBlob | payload | Asset | `s-<ciphertext SHA256>` or `m-<revision SHA256>` |
| MopRequest | payload | Asset | `q-<device public-key fingerprint>` |

Enable the `recordName` queryable index for MopRequest (the request list uses a
zone-scoped all-records query). Do not add indexes on payloads. All writes use a
custom `mop-<UUID>` zone; no public database permissions or share records are used.
Use CloudKit Console to deploy the tested schema to production before release.
Schema deployment is an administrative action, not an application startup task.
The implementation must never use `CKSyncEngine` or silently recreate deleted
zones during normal reads/writes.

The `payload` asset already contains mop ciphertext, or public metadata for
requests. A manifest contains the existing authenticated header and encrypted
index plus a map from secret record UUID to ciphertext hash. Reconstructing the
canonical v4 document authenticates the complete record table. A manifest's ID is
the hash of that complete document, not the hash of the manifest bytes.

Only the small head record is mutable. Its save uses the fetched record's system
fields and `.ifServerRecordUnchanged`. Immutable blobs are fetched and checked
before reuse. Any collision with different bytes fails closed. Interrupted staged
uploads are retained but are not reachable through committed history.

## Signed acceptance procedure (required before release)

Use disposable data in a development container and two Macs signed into the same
Apple Account. Use the same signing identity/App ID on both Macs, and isolated
`MOP_STATE_DIRECTORY` locations. Keep all recovery material offline after testing;
record the test vault UUIDs for deliberate cleanup in CloudKit Console.

1. On A run `vault init personal`, write at least two secrets, export a v4 backup, and verify
   the values. Inspect CloudKit Console: it must contain no plaintext secret value
   or secret reference. Note the authenticated vault fingerprint independently.
2. On B list/use the UUID, publish `device request`. On A approve it after comparing
   B's displayed fingerprint. On B use `vault trust` with A's fingerprint and read.
3. Edit one secret on A. On B sync/read and confirm unchanged encrypted secret
   records are reused. Check that both caches have the same canonical revision.
4. Start concurrent writes from both Macs. A stale head save must return code 11;
   verify the winning value, then retry the losing command. Never accept silent
   last-writer-wins replacement.
5. Authenticate a read on B, disconnect the network, and verify an explicit
   `read --offline`. Ordinary online reads must fail rather than use the cache;
   `write --offline` must fail before accepting secret input. Reconnect.
6. Remove B on A. Confirm the head changes only after all rotated records exist.
   B's online read fails; A still reads. Previously cached offline data remains
   accessible to B by design. Re-enrollment requires explicit approval/recovery.
7. Re-pin the new fingerprint on another remaining Mac. Restore an older revision
   and confirm the removed device is not reinstated. Exercise recovery into fresh
   local state with the offline key and independent fingerprint.
8. Interrupt a process during staging and just after head submission. `vault sync`
   must report committed/not-committed without replaying mutations; repeat after
   key rotation. Test quota/throttling handling and a deleted test zone.
9. Sign out/change accounts and verify isolation. No previous default/cache may
   silently become the other account's vault. Explicit offline reads cannot prove
   an unobserved account change or remote revocation.
10. Repeat authentication checks with default password fallback and strict
    biometric mode. Run the separately provisioned enclave probe's no-prompt
    denial and foreign-access-group checks from VALIDATION.md.

After development acceptance, promote the schema and package Production. Use a
new disposable production vault for initialize/write/read/export on a signed
build. Record build identity, macOS versions, environment, UUIDs, and test results.
**Do not publish a release until these checks pass.**

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

Exports are encrypted v4 documents and can be imported only into an absent head.
An import is an explicit creation operation; it may recreate a previously deleted
zone after verification. Import does not bring along older external history files.
There is no automatic history/staging garbage collector yet. Delete disposable
zones in CloudKit Console after acceptance and remove only their isolated local
state/Keychain items. Never delete a live device's key as test cleanup.

## Named vaults (0.5)

New manifests use `mop-cloud-manifest-v2`, containing `mop-vault-v4` headers
with a required name. The encrypted index maps relative `item/[section/]field`
paths to record IDs. UUID-based zones and record encryption remain unchanged;
the existing v3 cryptographic domain strings are retained because their key-wrap
and value-encryption protocols are unchanged. Header names are included in index
associated data, so changing an unauthenticated discovery name cannot authorize
access. Rename publishes a normal revision without uploading new secret blobs.
Restoring history retains the current name and authorization.

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
