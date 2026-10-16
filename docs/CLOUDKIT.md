# V3 item CloudKit schema

The native clients use one `ItemVaultSyncRuntime` and one CKSyncEngine per private account/database. Trusted vaults use `MopContent3-UUID`; account coordination uses `MopCoordination3`. Initial zone inventory seeds discovery; subsequent zone/account changes maintain the local index. Addresses never establish trust. CKSyncEngine owns the `mop-content-v3-private` subscription and transport retries; the application delegate only registers for notifications and routes wake hints.

| Zone | Type | Record name | Fields |
| --- | --- | --- | --- |
| Vault | `MopMembershipControlV1` | `membership-head`, immutable membership digest | `membership`: Bytes |
| Vault | `MopContentHeadV3` | item/settings UUID | `payload`: Bytes, `asset`: Asset or `assets`: Asset list |
| Vault | `MopContentVersionV3` | item UUID + version UUID | `payload`: Bytes, `asset`: Asset or `assets`: Asset list |
| Recipient grant zone | `MopContentGrantV3` | item UUID + signed grant digest | `payload`: Bytes |
| Coordination | `MopCoordinationDiscoveryV3` | kind + vault UUID + identity UUID | `payload`: Bytes, or `asset`: Asset |
| Coordination | `MopCoordinationEnrollmentRequestV3` | same routing pattern | `payload`: Bytes |
| Coordination | `MopCoordinationEnrollmentApprovalV3` | same routing pattern | `payload`: Bytes, or `asset`: Asset |
| Coordination | `MopCoordinationEnrollmentAcknowledgmentV3` | same routing pattern | `payload`: Bytes |
| Coordination | `MopCoordinationGrantRequestV3` | same routing pattern | `payload`: Bytes |
| Coordination | `MopCoordinationDeletionV3` | same routing pattern | `payload`: Bytes, or `asset`: Asset |

Names use colon separators; the codecs define canonical UUID casing. Inline payloads are limited to 512 KiB, grants to 16 KiB, coordination approvals to 16 MiB, deletion notices to 1 MiB and other coordination messages to 256 KiB. Existing content size limits apply; larger content uses 16 MiB asset chunks. Downloaded assets are copied into the durable inbox before an engine token can advance. The account inbox budget is 256 MiB with the specified single-record exception; quarantine payloads are limited to 32 MiB.

Membership genesis and head commissioning are durable operations. Membership advancement uses conditional head writes and exact readback after an uncertain result. Only independently verified committed heads advance trust. Content publication sends an immutable version before its mutable head; only the exact head echo confirms its receipt. Grants are independently signed and delivered.

Deletion notices retain the signed terminal statement and its authenticated membership history, so returning devices can verify against their independent pins after the item zone has been deleted. Removing a cloud zone without a verified notice never authorizes local erasure. Completed enrollment relays are deleted only after the recipient's durable acknowledgment; compact receipts remain for 30 days. Legacy `MopItems-*`, enrollment and deletion zones remain untouched.

## Release validation

Use the same signed container, environment, App Group and Keychain access group for app, CLI and AutoFill. Export the complete Development schema, add these types without dropping existing types, validate it, and inspect it before any explicit Production deployment. Do not reset schema or publish a real deletion notice as a probe. This implementation does not deploy schema.

Independent cryptographic review and signed physical macOS/iOS tests must pass before Production activation. Test disposable vaults with offline edits, enrollment during editing, relaunch, missing notifications, locked prepared transfers, background suspension, recovery, returning old devices and deletion interruption. Require convergence at the next execution opportunity without Refresh. OS scheduling does not promise background delivery by a fixed time. Subscription/billing synchronization and cross-account sharing are separate systems.

Production connections are disabled unless `MopAppSupport` is compiled with `MOP_CONTENT_SYNC_V3_REVIEWED`. Leave this condition absent until schema validation, independent cryptographic review and physical-client acceptance are recorded. This flag is not enabled by this change.
