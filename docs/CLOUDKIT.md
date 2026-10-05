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
