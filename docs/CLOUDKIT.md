# CloudKit v7

Use the provisioned container and environment. Development and Production identities/state are separate. Deploying schema to Production is an explicit release operation; this implementation work has not deployed it.

Each vault uses a custom zone `mop-v7-UUID`. Old zones are never discovered, migrated or deleted by v7. Record types:

| Type | Record name | Fields |
| --- | --- | --- |
| `MopV7Attachment` | `attachment-` + SHA-256 of encrypted attachment bytes | `payload`: Asset (application encrypted) |
| `MopV7Revision` | SHA-256 of exact canonical revision bytes | `payload`: Asset (already application encrypted/signed) |
| `MopV7Enrollment` | `enrollment` | `payload`: Asset (bounded public enrollment mailbox) |
| `MopV7Head` | `head` | `digest`: String; `operation`: String (fresh UUID, also for a same-digest fence) |

System fields supply change tags. Upload the immutable asset first, then conditionally save the head using `CKModifyRecordsOperation`, `.ifServerRecordUnchanged`, and `isAtomic = true`. A same-zone head operation is not atomic with prior uploads or participant permission changes. Never infer success/failure solely from a timed-out response.

A nonpublic `CKShare(recordZoneID:)` shares the whole zone. Owner devices look up participants by the independently verified request's account record ID; viewers receive read-only permissions, editors read-write. Device approval remains an independently signed roster change. Acceptance validates metadata's container, zone UUID, actual owner identity and nonpublic permissions, and uses the actual owner name in the shared database. Never substitute `__defaultOwner__` for a shared owner. Unexpected identity aliases fail closed.

Account/member identifiers include container, environment and account record ID. Signed device requests bind this scope and both public keys. A share URL is transport information, not trust evidence. The receiving device must compare the invitation's checkpoint independently. Both private and shared database subscriptions are hints; signed verification determines what becomes an offline checkpoint.

The real private-database adapter, assets, conditional head and version fence have passed on one account. Participant-side identity mapping, share acceptance, permission changes and concurrent shared writes still require a second actual Apple Account. [Validation](VAULT-NEXT-VALIDATION.md) separates those gates from modeled tests.

## Apple platform and vault trust

The native transport constructs `CKContainer` only after checking the signed
container/environment configuration. It uses `privateCloudDatabase` for the
owner and `sharedCloudDatabase` for accepted participants, checking the current
account around operations. Apple [container entitlements](https://developer.apple.com/documentation/cloudkit/ckcontainer),
[provisioning](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
and the [authenticated private database](https://developer.apple.com/documentation/cloudkit/ckcontainer/privateclouddatabase)
are security layers, not merely routing details. Apple Account credentials alone
do not authorize an arbitrary native client to write this container.

2ndPass adds independent Secure Enclave device identities, signed vault membership
and per-item key envelopes. Applicable OS sandboxing is another layer: the Mac
extension enables App Sandbox, but the packaged Mac app/CLI do not. See the
[composed trust model](SECURITY.md#composed-apple--2ndpass-trust-model).
No code directly queries Apple's private iCloud Keychain trust circle.

## Startup discovery

The client enumerates private and shared database zones using Apple's
`CKFetchRecordZonesOperation.fetchAllRecordZonesOperation`, retaining only
`mop-v7-UUID` locators. These are untrusted enrollment hints, not checkpoints.
Discovery creates no local trust pin and opens no device keys. Account identity
is checked before and after enumeration; failures are not treated as no vaults.
Actual multi-device discovery remains a physical acceptance check.

Engine validation uses Development-only `mop-v7-probe-UUID` zones. These are
excluded from user discovery, and their cache bindings include the probe namespace.
The public application-service probe must use a separately provisioned test
container rather than the normal application container.

## Shared-zone enrollment design detail

Cross-account vault sharing is not yet implemented as a supported feature.
Preliminary `share(with:role:at:)` code shares the zone containing enrollment.
Apple documents [shared-zone record access](https://developer.apple.com/documentation/cloudkit/shared-records).
When implementing sharing, preserve account-private enrollment storage: the
owner's private-database view alone would not establish exclusive write access
after a writable zone share. Self-signed request scope does not identify the
CloudKit writer of each exchange. Resolve and validate this design detail before
completing sharing; it is not a current product vulnerability. See
[the design review](SECURITY.md#shared-zone-enrollment-exposure).

## Automatic own-device enrollment

The owner-side private vault zone (potentially shared as described above) contains one `MopV7Enrollment` record with at most 32
exchanges and a 16 MiB encoded limit. Requests bind account/container/environment,
vault, device keys, name, nonce and one-day expiry with a device signature.
Invitations reference an already-published checkpoint digest (older inline
checkpoint packets are still accepted); acceptances use the signed membership
protocol. The `approved` field is a publication marker, not a checkpoint or grant.
The mailbox is trusted for same-account bootstrap identity, but only a verified
signed membership revision supplies the cryptographic grant.

Every mailbox write uses server change tags and if-server-record-unchanged saves.
Conflicts are re-fetched by polling. Approval publishes the signed vault revision
through the durable publication journal first, then updates the mailbox. A lost
acknowledgement can be reconciled and retried without repeating membership grants.
The receiving device verifies the approved descendant chain, its membership and
the accepted invitation nonce before adding a local registry entry.

The ordinary app flow automatically exchanges requests and acceptances while an
existing owner is unlocked, online and able to process them. It does not require
human code comparison. The implementation retains transcript fingerprints and
manual CLI confirmation/approval commands, but these are not a required security
boundary of automatic enrollment. Cloud `confirmedCode` is never local consent.

This intentionally composes Apple's authenticated, provisioned client access with
2ndPass's cryptographic membership. An attacker able to operate an authorized
client in the user's Apple environment and access this private container may
submit a request and receive a grant if an unlocked owner processes it. A
compromised bootstrap mailbox may substitute the initial owner checkpoint for a
joining device. Existing pinned devices still verify descendants. This is not a
claim that account-password possession alone grants container access. Cross-account
sharing instead requires independent checkpoint/fingerprint verification and
explicit owner approval.

The mailbox carries public keys, device labels, invitations and acceptances,
not private keys or plaintext secrets. Its self-signatures prove key possession,
not remote attestation of Secure Enclave hardware or client binaries.

Deploy `MopV7Enrollment.payload` (Asset) along with the existing types for
Production. There are no query-index requirements: the mailbox has a fixed record
ID. Existing database subscriptions cover mailbox changes. Live multi-device
CloudKit mailbox/notification behavior remains unverified in this session.

## External attachment assets

`attachment-blobs-1` revisions authenticate ciphertext digests/sizes and key
envelopes. Upload all new immutable blobs before uploading the signed revision
and conditionally publishing its head. Fetching/verifying revisions never fetches
attachment assets. Device Settings controls eager caching; AutoFill opts out.
Ciphertext caches are scoped by account and complete vault address and are not
synced or exported implicitly. Backups explicitly bundle all referenced blobs.

Deploy `MopV7Attachment.payload` (Asset) to Production as part of the release.
This code change does not deploy the CloudKit schema. Orphan/history blobs remain
until a future reachability-aware collector or complete zone deletion.
