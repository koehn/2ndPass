# Item CloudKit schema

Current application entry points use `ItemVaultSyncRuntime` and `CloudKitSyncAdapter`, backed by a device-local Core Data store. Validate the configured Development schema before an explicit Production deployment; device checks do not establish Production readiness.

Each owned private vault uses a custom zone `MopItems-UUID`. A single CKSyncEngine handles the trusted, commissioned zones in one account/database. The independently pinned control record must be verified before item publication; zone creation is controlled by durable commissioning state, not queued blindly into CKSyncEngine.

| Type | Record name | Fields |
| --- | --- | --- |
| `MopMembershipControlV1` | `membership-head` or the immutable membership name | `membership`: Bytes containing signed public authority |
| `MopEncryptedItemV1` | item/settings UUID | `envelope`: Bytes for small encrypted envelopes, or `envelopeAssets`: Asset list for larger envelopes |

The adapter uses inline bytes through 512 KiB and 16 MiB asset chunks above that. These are encrypted complete item envelopes; independent attachment/blob transfer is still pending. CKSyncEngine handles change tokens, native push scheduling and retry behavior. Durable Core Data mutations and receipts bridge process exits. No automatic `NSPersistentCloudKitContainer` mirroring is enabled alongside it. Shared recipient enrollment and CKShare creation remain unavailable.


## Enrollment and provisioning

The private `MopEnrollment-v1` zone relays scoped enrollment packets using `MopMembershipControlV1.membership`. Discovery and relay fetching complement CKSyncEngine item transfer. An existing device must be unlocked to sign admission and rewrap keys.

Persist commissioning intent before control publication. Verify independently pinned signed membership history/head before permitting item uploads. Once control publication may have reached the server, a missing zone is a recovery condition, not permission to silently recreate it. Discovery alone never installs a trust pin.

Provision the app, AutoFill and separate CLI for the same container, environment, App Group and Keychain access group. Validate with disposable zones and signed clients. See [validation](VALIDATION.md) and [architecture](VAULT.md).

## Permanent vault deletion

Updated clients use a separate private zone, `MopVaultDeletions1`. Add this record
before enabling Production deletion:

| Type | Record name | Fields |
| --- | --- | --- |
| `MopVaultDeletionV1` | vault UUID | `notice`: Bytes, maximum 1 MiB |

Use the same private-record permissions as the existing owner records. Notices
are create-only, owner-signed terminal statements rooted in independently pinned
membership. They include account/container/environment/zone binding and the
shared genesis digest, not a device-local setup receipt. Never expire or delete
these notices. They contain public authorization history but no vault name or
secrets. No query indexes are needed; clients fetch by record ID.

Deletion is available in Development. Production initiation is disabled unless
`MopAppSupport` is built with `MOP_VAULT_DELETION` (Xcode Swift active compilation
conditions, or SwiftPM `-Xswiftc -DMOP_VAULT_DELETION`). Keep that condition absent
until the schema is deployed and two signed devices pass the checks below.
Receiving authenticated notices and retrying existing operations do not depend
on the initiation flag.

1. Export the current Development schema with `cktool`, add the record type and
   bytes field, validate, and import the complete schema without dropping existing
   types. Review and deploy the schema in CloudKit Console before enabling the
   Production build condition. Never reset the schema or create a real deletion
   notice as a schema probe.
2. On disposable vaults, confirm typed-name deletion and
   `sp vault delete --vault UUID --confirm UUID`. Verify that history and pending
   edits disappear, a second connected device purges its copy, and an offline
   second device purges after reconnecting.
3. Interrupt after notice publication and after zone deletion, relaunch, then use
   the app's retry action or `sp vault sync`. Verify completion, keychain/cache
   cleanup, and preservation of another vault and exported backups.
4. Verify an older client does not recreate the missing zone. Older/offline
   clients and exported backups cannot be remotely erased by this protocol.

The local journal distinguishes prepared, publication uncertain, committed,
cloud deleted, and complete. Uncertain publication blocks access until resolved.
The authenticated commitment atomically removes ciphertext and the outbox; cloud
zone deletion and scoped cache/key cleanup are idempotent retries. A missing zone
without a verified notice never authorizes local erasure. This is logical deletion,
not a guarantee of forensic erasure of SQLite pages, OS snapshots, or backups.
