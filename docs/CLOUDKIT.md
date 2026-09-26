# CloudKit v6

Use the provisioned container and environment. Development and Production identities/state are separate. Deploying schema to Production is an explicit release operation; this implementation work has not deployed it.

Each vault uses a custom zone `mop-v6-UUID`. Old zones are never discovered, migrated or deleted by v6. Record types:

| Type | Record name | Fields |
| --- | --- | --- |
| `MopV6Revision` | SHA-256 of exact canonical revision bytes | `payload`: Asset (already application encrypted/signed) |
| `MopV6Enrollment` | `enrollment` | `payload`: Asset (bounded public enrollment mailbox) |
| `MopV6Head` | `head` | `digest`: String; `operation`: String (fresh UUID, also for a same-digest fence) |

System fields supply change tags. Upload the immutable asset first, then conditionally save the head using `CKModifyRecordsOperation`, `.ifServerRecordUnchanged`, and `isAtomic = true`. A same-zone head operation is not atomic with prior uploads or participant permission changes. Never infer success/failure solely from a timed-out response.

A nonpublic `CKShare(recordZoneID:)` shares the whole zone. Owner devices look up participants by the independently verified request's account record ID; viewers receive read-only permissions, editors read-write. Device approval remains an independently signed roster change. Acceptance validates metadata's container, zone UUID, actual owner identity and nonpublic permissions, and uses the actual owner name in the shared database. Never substitute `__defaultOwner__` for a shared owner. Unexpected identity aliases fail closed.

Account/member identifiers include container, environment and account record ID. Signed device requests bind this scope and both public keys. A share URL is transport information, not trust evidence. The receiving device must compare the invitation's checkpoint independently. Both private and shared database subscriptions are hints; signed verification determines what becomes an offline checkpoint.

The real private-database adapter, assets, conditional head and version fence have passed on one account. Participant-side identity mapping, share acceptance, permission changes and concurrent shared writes still require a second actual Apple Account. [Validation](VAULT-NEXT-VALIDATION.md) separates those gates from modeled tests.

## Startup discovery

The client enumerates private and shared database zones using Apple's
`CKFetchRecordZonesOperation.fetchAllRecordZonesOperation`, retaining only
`mop-v6-UUID` locators. These are untrusted enrollment hints, not checkpoints.
Discovery creates no local trust pin and opens no device keys. Account identity
is checked before and after enumeration; failures are not treated as no vaults.
Actual multi-device discovery remains a physical acceptance check.

Engine validation uses Development-only `mop-v6-probe-UUID` zones. These are
excluded from user discovery, and their cache bindings include the probe namespace.
The public application-service probe must use a separately provisioned test
container rather than the normal application container.

## Automatic own-device enrollment

The private vault zone contains one `MopV6Enrollment` record with at most 32
exchanges and a 16 MiB encoded limit. Requests bind account/container/environment,
vault, device keys, name, nonce and one-day expiry with a device signature.
Invitations, acceptances and approved encrypted checkpoints reuse the v6 signed
membership protocol. This mailbox is untrusted transport; it grants no keys.

Every mailbox write uses server change tags and if-server-record-unchanged saves.
Conflicts are re-fetched by polling. Approval publishes the signed vault revision
through the durable publication journal first, then updates the mailbox. A lost
acknowledgement can be reconciled and retried without repeating membership grants.
The receiving device verifies the approved descendant chain, its membership and
the accepted invitation nonce before adding a local registry entry.

Both devices display a 96-bit truncated SHA-256 fingerprint of the request and
invitation transcript. The new device records a local code-match confirmation, and the owner explicitly
confirms matching codes before approval. The client never adopts a confirmation
field from cloud state; even an apparently approved response cannot substitute
for that local trust decision. This human comparison authenticates the bootstrap; neither iCloud
record possession nor a self-signed request establishes a trusted owner key.
A server can suppress requests or forge denial, but cannot thereby grant access.
The mailbox includes public keys, device labels and encrypted checkpoint metadata;
it contains no private keys or plaintext secret values.

Deploy `MopV6Enrollment.payload` (Asset) along with the existing types for
Production. There are no query-index requirements: the mailbox has a fixed record
ID. Existing database subscriptions cover mailbox changes. Live multi-device
CloudKit mailbox/notification behavior remains unverified in this session.
