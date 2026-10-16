# Recipient grant zones and readable versions

Recipient-specific grant zones are the sole supported grant location. Existing
current-format zones, identities, keys and local work remain in place. There is
no old-zone migration, copying, routing fallback or grant-maintenance workflow.

## Layout and CloudKit API evidence

- `MopContent3-<vault UUID>` retains encrypted heads, immutable content versions,
  and membership control records. The account coordination zone is unchanged.
- `MopGrants4-<vault UUID>-<recipient fingerprint>` holds the existing signed grant
  record type and `<item UUID>:<grant identifier>` record names. A recovery key
  is a separate recipient. Canonical UUID and lowercase digest parsing is strict.
- These are custom zones in the **private database of the same account**. The
  common content zone is shared by enrolled devices, not a new `CKShare` or a
  change to cross-account authorization. Routing is not cryptographic isolation.

Inspected the installed CloudKit Swift interface and `CKModifyRecordsOperation.h`,
and Apple's documentation for [fetch scopes](https://developer.apple.com/documentation/cloudkit/cksyncengine-5sie5/fetchchangesoptions/scope-swift.enum),
[CKSyncEngine](https://developer.apple.com/documentation/cloudkit/cksyncengine-5sie5),
[custom zones](https://developer.apple.com/documentation/cloudkit/ckrecordzone),
and [atomic modification](https://developer.apple.com/documentation/cloudkit/ckmodifyrecordsoperation/isatomic).
Fetch and send scopes are independent. Atomicity is within a zone; it cannot make
content and recipient grants arrive together. Therefore no cross-zone atomic
assumption is used. `CKShare` would grant CloudKit access, not replace signed
membership or per-device key wrapping, and is unnecessary for this account model.

Automatic and explicit fetches use an allowlist: trusted content zones, the
coordination zone, the locally enrolled recipient, and a recovery recipient only
while its key has explicitly been presented. Discovery of a grant zone does not
subscribe to it. Publication provisions its destination independently. Saved-record
acknowledgments and conflict readbacks enter the durable, verified inbox directly;
they do not expand the fetch allowlist. A signed grant request can repair one
record in another recipient's zone without reading that zone's history.

## Durable reads and readiness

Readable references contain only version, key generation, recipient, and grant
identifier, scoped by account/database/zone owner/vault/item. Both signatures and
the membership path are checked before creating a reference; decryption still
uses the device's existing key provider. References point to retained encrypted
history. They never cache plaintext or a new wrapping key. The accepted head can
advance without advancing a readable reference. A later grant enables promotion;
a grant arriving first waits durably for its source content. Normal read promotion
commits only after the requested projection decrypts successfully, with a head CAS
and a shared vault-boundary write to detect cross-process races. A failed unwrap
or projection leaves the previous reference intact. Device and recovery reads use
the same recipient-bound selection. Reads can continue from the old reference
after lock/restart. Edits still compare against the current
head, so a stale readable version cannot overwrite a newer head.

Initial local reference seeding has its own durable, vault-scoped
`readable-initialized` checkpoint. Launch and sync routing check it before reading
the item revision index. The first pass preserves existing references and verifies
only missing ones; a failed or cancelled pass does not mark completion. Completed
seeding is not repeated for later routing calls or process restarts. Ordinary
verified reads continue to establish and advance references for newly arrived
items, recipients and versions. The checkpoint is local progress only, never
proof of authorization or cloud readiness, and uses no retired migration state.

Readiness directly verifies current content, recipient grants and download
checkpoints. It does not depend on migration receipts. Missing destination grants
invalidate only the affected delivery evidence and queue the exact prepared grant
through normal publication authority checks. Repair markers survive restart and
clear on confirmed delivery. Local readable history and unrelated recipients'
receipts are retained.

## Removal, recovery and retention

Device removal retains signed membership verification and schedules current key
rotation. Recovery coverage includes the recovery recipient and current content;
reconnection does not restore obsolete publication authority. Recipient-zone
provisioning and exact publication readback remain part of normal operation.

Vault deletion verifies its signed notice before routing or provisioning. Local
cleanup and cloud deletion remain durable, resumable operations. The cleanup of
retired implementations itself never deletes live data, resets devices, changes
signing identities or deploys schema.

Normal receipt/history retention remains. No automatic grant garbage collection
replaces the removed maintenance ceremony. There is no review/apply/status UI,
archive-validation ceremony, old-zone deletion runner or maintenance CLI operation.

## Physical acceptance still required

Use disposable vaults on signed devices to verify automatic enrollment, delayed
cross-zone delivery, restart while a grant is missing, recovery coverage, device
removal rotation and interrupted whole-vault deletion. Confirm a returning device
observes deletion before provisioning zones. Inspect account/environment isolation
and the recipient fetch allowlist. Software tests and simulator builds cannot prove
real iCloud delivery, Secure Enclave authorization or cross-account permissions.
