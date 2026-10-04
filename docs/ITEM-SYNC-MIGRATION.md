# Item-level CloudKit migration

This migration is in progress. GUI, CLI and AutoFill now use `ItemVaultService`; the active v7 service, registry, snapshot downloads and restore journal have been removed. No old CloudKit zones or user data are automatically removed. Existing v7 vaults must be restored from a portable archive into new vaults. This is a source cutover, not release acceptance or an installed-app upgrade.

The obsolete v7 revision/publication engine, checkpoint adapter, enrollment exchange, attachment transfer and per-vault native sync wrapper have been removed. The unbuilt pre-v7 `MopVault`/`MopCloudKit` modules, obsolete software-key identity backend and their tests have also been removed. Shared hardware/crypto primitives remain. The old `MopVaultNextCheck` executable was retired; `sp-keychain-check` remains. Historical audit/reproducer documents should be used against their original Git revision.

## Current client integration

- Core create/restore, discovery, catalog, explicit reads, item edits, history, trash/restore, rename and local portable export use the new multi-vault service.
- All clients use the shared App Group store. CLI is a separate authenticated client, not a second isolated replica. It requests work from the sync owner or acquires the lease itself. Isolated cloud state directories are rejected.
- GUI saves acknowledge the local transaction. CLI defaults to waiting for exact cloud receipts (20 seconds); `--local-save` returns after local durability. Timeout preserves and reports queued work.
- Store notifications refresh the UI, deferring safely while an editor or sheet is active. Old enrollment and periodic cloud-refresh polling have been removed.
- GUI lists reopen from device-encrypted, independently stored local catalog rows.
  A vault session unwraps one catalog key, then decrypts display rows symmetrically;
  unchanged items do not require hardware key operations or fetching item bodies.
  Visible fields/search metadata persist encrypted; concealed values and item keys
  do not. Missing, changed or damaged rows are projected in bounded background
  batches. The old whole-vault display-decryption function and normal unlock
  rebuild progress UI are removed. First upgrade/cache recovery may prepare the
  catalog once; download/key-access progress remains distinct.
  Lock clears the catalog key and plaintext views. Exact item reads and edits
  retain authoritative source/version checks. Complete command catalogs, exports,
  mutation validation and AutoFill never treat partial display state as complete.
- Same-account private vault discovery and automatic device connection are implemented. Shared vaults, device removal, recovery, general document import, credential-account management and permanent vault deletion remain unavailable through capabilities. There is no fallback to the deleted service. Separate device-local hardware credentials remain available.
- Conflict review UI, membership advancement, independent attachment transport and remaining physical-device release checks remain required. This partial feature set must not be presented as release-ready sharing support.

## Automatic connection on the same Apple Account

The user confirmed acceptance of the backup, large-vault responsiveness and CLI
lookup slice on 2026-10-03. The next slice adds remote private-zone discovery and
automatic additive device admission. Newly discovered vaults appear as connecting;
they do not trigger personal-vault creation or require an access request, manual
approval or comparison code. Encrypted vault names become available after key
access arrives. An empty local database is not evidence of an empty iCloud
account: first-device discovery must finish successfully before offering creation.
Already-connected vaults open locally while remote discovery runs in the background.

The authenticated same-Apple-account **private CloudKit database is now an
explicitly accepted bootstrap trust channel**. Discovery alone never installs a
pin. The new device signs a scoped, durable enrollment packet using device-local
keys; an unlocked existing device automatically signs the additive membership
successor and rewraps item keys. The joining device checks its exact original
packet, account/container/environment/vault/device bindings, signed history and
its ability to decrypt vault metadata before installing device-only trust.
Existing trust pins and immutable successor checkpoints cannot be replaced by a
new cloud-supplied root. This does not protect initial enrollment against an
attacker able to write through the same trusted iCloud account/container channel.
No new-device approval by the human is required under this account trust model.

CloudKit's [zone discovery](https://developer.apple.com/documentation/cloudkit/ckdatabase/allrecordzones%28%29)
and [zone change fetching](https://developer.apple.com/documentation/cloudkit/ckdatabase/recordzonechanges%28inzonewith%3Asince%3Adesiredkeys%3Aresultslimit%3A%29)
provide the discovery and enrollment relay; CKSyncEngine continues to transfer
item records. The relay uses the private `MopEnrollment-v1` zone and existing
`MopMembershipControlV1.membership` field. Foregrounding, cloud notifications and
unlocking resume work without an application polling timer. Notifications are
hints, so reopening/foregrounding also reconciles. An existing device must be
unlocked to use its hardware keys; iCloud account authentication does not unlock
Secure Enclave keys on its behalf.

Admission stages encrypted replacements durably, conditionally advances the
signed cloud membership head, then atomically activates the local item/outbox
batch. Lost acknowledgements retry the same signed operation. Concealed field,
history and attachment ciphertext remain unchanged; recipient wrappers and
metadata are updated. Approved grants remain resumable after the initial packet
expires. Canceled/restarted packet transcripts are retained to recover a grant
issued concurrently with cancellation. None contain device private keys.

The joining device downloads a small, verified metadata record before opening,
then downloads items in the background. The signed admission now includes the
existing device's item-record count (including tombstones, excluding metadata).
The joining store saves this as a scoped, durable initial-download hint in the
same transaction as metadata installation. Until that many records arrive, the
UI shows “Connected to iCloud · Downloading items” instead of an empty-vault
prompt, even before the first record arrives or after restarting. Local opening
and key-wrapper waiting states continue afterward where needed. The hint is
removed once satisfied; it does not claim an exact live cloud total or transfer
percentage, authorize data, or prove a backup is complete. Concurrent changes
can make the snapshot count approximate. Older admission packets without the
optional count retain their previous presentation behavior. Update both devices
for new connections to use this hint.

Locally known older items the joining device cannot yet
unwrap stay in a waiting count; incomplete projections never become complete
exports or AutoFill inventories. An existing device can rewrap older additive
membership records and offline local edits without decrypting their fields.
Obsolete local mutation receipts become superseded, never falsely confirmed;
real content conflicts remain conflicts. This adds devices only: removal, roles,
key revocation and cross-account sharing still need their own workflows.

The user confirmed on 2026-10-03 that vault discovery, automatic admission and
item delivery succeeded on the physical iPhone; the initial empty presentation
prompted this follow-up.

The next physical run also confirmed eventual access to every vault, but exposed
repeated unlock clicks and a flickering indicator. The UI now retains the initial
connection intent until a vault opens; later admitted vaults load in the existing
session. While waiting for key access, the lock screen shows a continuous
connection state rather than offering repeated unlock attempts. Manual lock and
operation failures clear that intent. Short local catalog refreshes no longer
control the cloud spinner. Initial item readiness has a count-based progress bar;
key preparation remains indeterminate because no trustworthy work total is
available before admission. This presentation change does not remove the existing
device's cryptographic rewrapping or subsequent catalog revalidation.

**Enrollment accepted by the user on 2026-10-03**, following the automatic
connection and progress-display follow-ups. This closes the same-account device
enrollment acceptance gate. It does not establish acceptance of cross-account
sharing, revocation, conflict handling or every offline-edit scenario. Those
remain separate release checks. No cloud zones or backup data were deleted.

**Same-account synchronization accepted by the user on 2026-10-04.** After
confirming enrollment on all devices, the user confirmed these physical tests:

- Create an item on iPhone; it appears on Mac and iPad.
- Edit that item on Mac; the change reaches both other devices.
- Edit offline on iPhone, reconnect, and the edit uploads without manual Refresh.

This closes the reported iPhone enrollment/synchronization incident for those
scenarios and supersedes the pending physical confirmation notes below. These
are user-reported device results, not simulator test results. Concurrent edits to
the same item, conflict resolution, cross-account sharing and revocation remain
separate acceptance gates.

## Device-local encrypted display catalog

The catalog is derived data in the existing Core Data `StateBlob` entity: one
signed device-wrapped catalog key per vault and one independently AEAD-encrypted
row per item. Reusing the existing entity avoids migrating the programmatically
constructed Core Data model. The rows are excluded from CloudKit publication and
portable archives; the app-group store directory is already excluded from backups.
The key context includes account, database, zone owner, vault UUID, device identity
and pinned genesis. Row authentication additionally binds key ID, item UUID and
source version. A catalog key is held only inside the authorized session permit
and released when locked or invalidated; item keys are never retained there.

Authoritative local item versions are the durable work ledger: a missing or
mismatched row needs projection. This includes changes received while locked or
before a process exits, so no separate notification-dependent queue is necessary.
Store notifications trigger reconciliation while the UI is active. Projection
commits compare source versions and the current cache-key envelope inside a Core
Data transaction; cross-process stale writers are rejected. Cache writes neither
queue cloud mutations nor explicitly wake synchronization. Removed items' derived
rows are pruned. A corrupt row is rebuilt individually; a corrupt key envelope
resets only derived catalog rows. Authentication failures still fail closed.

The list keeps the existing encrypted visible-field/search metadata, including
notes. Passwords, OTP seeds, attachments and private-key contents stay out of it.
Secret access still verifies the authoritative encrypted item. Cache authenticity
and version matching are not a new guarantee against rollback of an entire local
store or omission of remote changes. Conflicted items retain the repository's
conflict behavior. Additive enrollment still changes item versions and can require
reprojection; this work is not claimed eliminated by the cache.

Timing signposts under `com.koehn.mop` / `Catalog` measure display catalog
projection. Software tests bound hardware unwrap counts for 1, 40 and 1,200 items;
real mobile wall-clock timings still require the updated app. Acceptance: allow
one initial catalog preparation, lock/reopen, terminate/relaunch, repeat offline,
then change one item on another device and verify only that row is refreshed.

## Rollback and backup independence

[Portable archive v1](formats/PORTABLE-BACKUP-v1.md) specifies every byte of the archive/key formats and the logical JSON schema, limits and restore behavior. A copy is retained at `dist/migration-preservation/PORTABLE-BACKUP-v1.md`, outside tracked source. Copy it somewhere retained across `git clean -x` before discarding the tree. It is sufficient to regenerate an archive reader after rollback; preserving current backup implementation code is not required. Alternatively return to a compatible earlier export and start again. Keep archives and their keys separately, and retain the original archive until the new restored vault is verified.

## Architecture

Use a local Core Data `NSPersistentContainer` in the App Group, with encrypted
payloads, transactional pending mutations, persistent history, and cross-process
change notifications. Partition the store by CloudKit container/environment and
records by account/database/zone owner/vault. Use CKSyncEngine for private/shared database transfer;
do not also enable automatic Core Data CloudKit mirroring. Ordinary item edits
are durable locally before publication. Drafts use item versions, not vault
revision hashes. Concealed fields remain encrypted until explicitly requested.

One process owns sync for an account/database at a time. The GUI normally owns
it; the CLI uses the same local store, requests synchronization, or takes the
lease when the GUI does not own it. The extension reads and writes the shared
store without running a competing long-lived engine. Authentication remains
per-client. The CLI defaults to cloud-confirmed writes, with an explicit local
save mode; timeout after local commit reports pending with receipt IDs and a distinct nonzero exit code, not a lost change.

Independent item versions are eventually consistent. A separate signed
membership history authorizes keys/roles; native CKShare governs transport
permissions. Read-write sharing permits changes to all shared records, so
signatures are still needed for membership authority and deletion/corruption can
deny service. There is no global cryptographic proof of item-set completeness.
Known obsolete-epoch writes are quarantined. Without a global publication fence,
stale writers may submit old-key ciphertext; later rejection cannot undo that
disclosure. Account removal and per-item rotation are distinct milestones.

## Backup first

The existing `.mopfile` is ciphertext tied to original device/recovery keys;
`vault import` reconnects to the existing cloud vault. Neither is an independent
portable restore. New commands use an authenticated, backend-neutral logical
archive and a generated key that is independent of existing vault keys:

```sh
sp vault backup --offline --vault VAULT_UUID /path/to/vault.moparchive --key-file /separate/path/vault.key
sp vault restore-backup /path/to/vault.moparchive --key-file /separate/path/vault.key --name restored --restore-id NEW_UUID --dry-run
sp vault restore-backup /path/to/vault.moparchive --key-file /separate/path/vault.key --name restored --restore-id NEW_UUID
```

Use a freshly generated UUID and retain it for retries. Restore creates a new
owned vault, never overwrites an existing vault, and does not reinstate old
sharing or device authority. Account recovery configuration is not restored by this archive. Device-local Secure Enclave keys cannot be exported.
The generated archive key is **not** the existing offline recovery key. Store it
separately; both the archive and its key are required. Neither output overwrites
an existing file. If key writing fails, keep the source and export again.

The archive preserves transferable field values, item metadata, retained history,
trash, attachment bytes, and cloud software credentials. Old hardware-credential
registration references remain informational and do not restore private keys.
The initial format is bounded at 256 MiB and the v7 restore must fit v7 capacity;
oversized archives fail rather than silently drop data. The shared repository partitions each vault and its pending work independently.

## Ordered gates and ownership

1. **Portable archive**: old-to-old restore on a fresh device identity without
   original cloud/key access; service/CLI/UI wiring; retain a compatible old
   source tag/build only after checks pass. A real user backup is a separate
   explicit export, not something a fixture test proves.
2. **Core Data repository**: real SQLite tests for atomic item/outbox changes,
   reopening, conflicts, engine state, process concurrency, and persistent history.
3. **New crypto and sync**: independently signed item envelopes, membership
   authority, engine delegate, crash reconciliation, and upload lock gating.
4. **New domain service**: item-level APIs, local observation, imports/history,
   sharing/recovery, conflict UI, and AutoFill/CLI adapters.
5. **Round trips and device validation**: old/new archive combinations, physical
   devices and two Apple Accounts, permissions, rotation, offline edits, and
   notification-driven UI updates.
6. **Cutover/removal**: the user authorized source replacement after verified
   backup/restore. Remove superseded routing now; keep remaining feature and
   physical acceptance gates explicit before release. Preserve old user zones;
   do not maintain dual writes. The standalone backup specification permits
   regenerating an adapter after rollback without retaining its implementation.

The control agent owns integration and gates. The design agent owns storage,
sync, and security review. The implementation agent owns archive/crypto work.
The test agent owns independent fixtures and is the sole SwiftPM/Xcode runner.
Follow AGENTS.md for sandbox and Apple validation; fixture/simulator results do
not establish real iCloud, Secure Enclave, or cross-account correctness.

## Implementation status

The user confirmed completion of real backup/restore on 2026-10-03. Before the
next implementation stage, the working source (including uncommitted backup
support) and installed restore-compatible signed CLI were preserved under
`dist/migration-preservation/v7-compatible-2026-10-03/`. The manifest records
the base Git revision and SHA-256 hashes. The copied CLI signature was verified
outside the sandbox. The installed binary and source snapshot are separate
artifacts, not a claim that the installed binary was built from that snapshot.
Preserve this directory alongside the user backup before cleaning build outputs.

Implemented foundations:

- Portable export/restore in the current service, CLI and UI, with authenticated
  read-back and a resumable restore ID. Fresh-identity restore fixtures do not
  depend on the source cloud zone or source device keys.
- Ciphertext-only Core Data repository with atomic pending mutations, durable
  delivery receipts, persistent history and native change notifications.
- CKSyncEngine adapter, private/shared scoping, exclusive process lease,
  durable sync requests and a notification-driven request consumer. A request
  being handled is not cloud confirmation. The CLI can await its actual receipt
  with a bounded, notification-driven wait.
- Independently signed item/settings envelopes and a separately pinned,
  append-only membership authority chain. Items bind the exact signed authority
  state, not only a hash of the member roster. Signed per-item revision numbers
  reject known older versions and equal-revision forks while allowing catch-up
  across skipped intermediate updates. An authorized editor can still write
  new content at a higher revision. This is not global inventory/fork proof;
  revision numbers are distinct from stable encryption-key generations.
- A scoped item domain session with per-item expected versions, durable saves,
  metadata-only catalog reads, explicit reveals and portable export. Locking
  closes private-key access; public-key ciphertext verification remains usable.
  Account or membership changes invalidate the verifier as well.
- Selective field edits with stable encryption-key generations, fresh record IDs,
  bounded retained history, and unchanged ciphertext reuse. Metadata changes
  decrypt the catalog only. Membership changes require explicit rekeying.
- Explicit conflict choices guarded by the complete reviewed snapshot. Discarded
  local receipts become superseded, never falsely cloud-confirmed. Preview shows
  metadata; revealing either version remains an explicit authenticated operation.
- Observable catalog state driven by repository notifications, with cheap version
  projections to avoid decrypting catalogs for receipt-only updates. Lock clears
  visible catalog state and prevents queued saves. The application now consumes service change streams and reconciles its catalogs.
- Local new-vault bootstrap from an authenticated portable archive or empty vault.
  A create-only, nonsynchronizing ThisDeviceOnly Keychain record pins the exact
  scope, source digest, name and genesis before a single Core Data transaction
  creates membership, encrypted items and pending uploads. Reopening and retries
  retain the same authority and preserve later edits. A lock after commit reports
  a distinct completed-but-locked outcome carrying the durable receipt. Parsing
  and encryption run away from the caller's actor, with lock checks between items.

Still required after this source cutover:

- Persist membership successors and discover enrolled vaults; connect native
  sharing, enrollment, recovery and resumable key rotation to the new model.
  Current ingress requires the current authority state. Historical local reads
  work, but new-client rollover of older item records is not yet implemented.
- Connect the local import API to application entry points; complete conflict UI
  and signed permanent deletion. UI observations, AutoFill and CLI operations now
  use the new domain service.
  Resolve concurrent display-name collisions explicitly: item UUIDs are stable,
  while legacy CLI paths and portable restore currently require unique names.
  A duplicate name must not silently merge items or drop either item's fields.
- Separate immutable encrypted blobs from the signed item manifest to avoid
  retransmitting unchanged ciphertext. Current v2 selective edits preserve bytes
  but still transfer the complete envelope. Proposed blob uploads become durable
  dependencies of manifest publication through CKSyncEngine. Its zone change
  fetching does not offer per-record desired-key filtering; first-sync/new blobs
  may download eagerly. On-demand decryption is separate from lazy transfer.
- Bound/clean retained asset staging, history, receipts and quarantine; add
  quarantine recovery and conflict UI. Invalid signatures never authorize a
  local overwrite, and missing assets must not silently advance durable tokens.
- Run physical-device/two-account acceptance before release. Real backup/restore
  and retention of the compatible signed CLI/source snapshot are recorded above;
  they do not establish acceptance of the new backend.

Physical iOS lock can make the protected store unavailable. Background execution
is opportunistic: local saves are durable once their transaction completes, and
unsent work resumes when the authorized sync owner can run again. Neither an
APNs notification nor a background scheduling request promises immediate sync.

## Cloud provisioning boundary

Local initialization is not cloud publication. Before opening the item upload
queue, provision the owned private zone and publish independently pinned signed
membership control records. Persist commissioning intent before the first control
write, and confirm the required history/head before allowing items to publish.
Shared recipients cannot provision an owner's zone. A server-provided genesis
never becomes a trust pin just because a zone is visible.

Zone creation may retry while durable state proves no control publication has
been attempted and no item publication has been permitted. Once control may have
reached CloudKit, a missing zone is a recovery condition, not permission to
silently recreate it. A network error alone is not evidence that the zone is
missing. Membership updates require authenticated successor verification and a
conditional head update; timestamps and item signatures do not establish that
an incoming membership head is current.

The private owner-only genesis path is implemented in the runtime. A native
provisioning transport creates an empty zone and conditionally creates an
immutable membership record plus the initial head; both are fetched and verified
against the independent pin before the persisted publication gate opens.
CKSyncEngine itself never queues zone creation. Provisioning and item sync use the
same account/database lease. Confirmed missing zones, deleted control records and
proven control mismatches durably close the gate.

`NativeItemCloudAccount` derives the account namespace from signed container/environment configuration and native Apple account identity, retaining a device-only marker for local access. Account-change notification retires that binding. `ItemVaultSyncRuntime` manages committed, independently pinned vaults through one adapter for the account/private database. The former per-vault wrapper is removed. Public verification works for unopened vaults; private-key operations require an authorized session. Store and durable sync-request notifications resume work without an application polling loop.

This slice does not advance membership, enroll another device, create CKShare,
or establish a global inventory proof. Shared/new-member scopes remain upload-denied
until their authenticated enrollment and control-history paths exist. Same-account additive successor histories are now verified and checkpointed; removal and cross-account membership changes remain blocked. Temporary inability to read
protected local trust is a retryable verification failure, not proof of a forged
control record. Native entitlement/account/hardware and real CloudKit acceptance
remain separate from fake-transport tests. Development schema creation and
production schema deployment must include `MopMembershipControlV1` and
`MopEncryptedItemV1`; source builds do not provision or deploy that schema.

## Local named-reference lookup

Field menus always include **Copy reference**; the developer preference controls
additional diagnostics only. Existing `sp://vault/item/field` references retain
their name-based semantics, including rejection of ambiguous duplicate names.

Fresh CLI reads use a disposable local encrypted name index instead of hydrating
all visible fields in the vault. The index is signed by the local device and
bound to its identity, vault scope and trusted membership. It contains no field
values or unwrapped item keys. It is local cache data, not a CloudKit record or
part of the portable backup format.

Before resolving a name, the session reconciles the index with the complete
local item/version inventory, decrypting metadata only for new or changed
items. It validates the selected item and version before revealing the field.
Missing or invalid cache data is rebuilt from verified encrypted items. The
first build on an existing device can still take time; a completed GUI catalog
load seeds the same cache for subsequent CLI processes. Authentication and local
store access remain necessary, but reads do not await cloud delivery. This
optimization does not establish that the local store contains the latest remote
changes.

## Validation recorded on 2026-10-03

- Existing-device reconnect: an owner can issue a fresh signed approval for an
  exact device public-key identity already in current membership. Its successor
  equals the final history state; the receiver verifies the owner's signature,
  request/scope binding and exact current identity without appending membership.
  New-device admission keeps the original successor rules. Runtime returns this
  grant before stopping the engine or preparing any item rewrites; an existing
  journal for the same request still resumes/replays the original admission.
  Missing local initialization now makes discovery report reconnect-needed even
  when independent Keychain pins survive. Reconnect may reuse that pin only when
  initialization is absent and genesis/scope/digest match; authenticated cloud
  metadata and pinned membership history still must validate. Existing stores
  are not reset. Tests cover same UUID/different keys, tampering, expiry, request
  mismatch, preserved pins with a fresh database, zero new outbox entries, and
  unchanged runtime membership/item versions. 29 crypto and 116 AppSupport tests
  passed, with focused runtime and crypto reruns. Validation logs:
  `/tmp/mop-reconnect-tests.log`, `/tmp/mop-reconnect-runtime-test.log`,
  `/tmp/mop-reconnect-security-tests.log`, `/tmp/mop-reconnect-ios.log`,
  `/tmp/mop-reconnect-macos.log`. Updated grant handling is required on both the
  joining and approving devices; real iCloud reconnect remains to be confirmed.
- Reinstall enrollment follow-up: the iPhone remains on Connecting securely
  before authentication. This does not prove a retained-Keychain/bootstrap
  mismatch. Automatic owner-side enrollment previously aborted the entire pass
  on one request's session-load or approval error; the outer catch hid the error.
  Requests now isolate those failures, rechecking cancellation/account authority
  before continuing. Notice/error logs report request counts, approval completion
  and error domain/code without request identities or payloads. The connecting
  screen exposes Retry Connection, which invalidates discovery and reruns normal
  automatic enrollment without resetting keys or data. UI regression covers
  retry while waiting and subsequent automatic unlock. 281 tests passed (UI165,
  AppSupport116); native build logs are `/tmp/mop-enrollment-retry-ios.log` and
  `/tmp/mop-enrollment-retry-macos.log`. Physical enrollment remains unconfirmed;
  the owner-side change must be installed on the unlocked Mac as well.
- Silent Refresh follow-up: the user reports only Core Data WAL messages and
  continued lack of bidirectional iPhone updates. WAL activity does not establish
  a cloud transfer. Engine registration now excludes unresolved conflict scopes
  using an atomic repository projection; previously it registered saves that the
  batch builder necessarily refused. Both local and remote versions remain in
  the repository. Resolution re-registers the chosen pending version. A regression
  covers restart durability, unrelated item eligibility and resolution requeue.
  Added `Sync trace:` notice logs at the UI wake, runtime setup, driver wake,
  fetch/send boundaries and callback record counts. Logs contain counts and
  booleans, not item/account identifiers or payloads. They distinguish an early
  return or stalled stage from a completed zero-change fetch. Physical-device
  recovery is not established. Tests: Sync 42, UI 165, AppSupport 116 passed
  (`/tmp/mop-sync-trace-tests.log`, final sync rerun
  `/tmp/mop-sync-queue-tests.log`).
- Conflict asset recovery follow-up: physical iPhone logs identify
  `unreadableRemoteRecord` while handling server-record-changed responses.
  The send delegate previously passed `error.serverRecord` directly to the
  encrypted asset reader. It now explicitly fetches the complete current record
  (including assets) by the failed record ID, checks the fetched identity, then
  uses the existing authenticated receive/conflict path. Account and engine
  generation checks surround the asynchronous operation. No local edits are
  discarded and no conflict is automatically resolved. The enclosing durable
  request handler no longer overwrites a suspended adapter's specific failure
  with a generic send error. Regression tests cover asset-backed fetch/decode,
  incorrect identity and fetch cancellation; 41 sync and 116 AppSupport tests
  passed (`/tmp/mop-conflict-assets-tests.log`, final sync rerun
  `/tmp/mop-conflict-assets-final-tests.log`). Real-device recovery remains to be
  checked; duplicate background-registration warnings remain an open lifecycle
  concern, not evidence that this payload fix failed.
- iPhone conflict diagnostics follow-up: physical logs show duplicate engine
  background registration, two `serverRecordChanged` responses and then the
  adapter's generic `storageFailure`. Enrollment history incorrectly caused
  catch-up to stop/recreate the engine on every wake, even with no older-epoch
  local envelopes. Runtime now checks for actual outstanding catch-up before
  taking the exclusive lease and stopping the driver. Preparation/commit retain
  their lease and version checks. Repeated manual wake regression coverage
  verifies the same engine remains active after enrollment catch-up.
  Sync event failures now log error domain/code, repository enum cases and an
  underlying error domain/code; no descriptions, userInfo or payloads are logged.
  Membership refresh errors are logged before mapping to `storageFailure`.
  **156/156 affected tests passed** (Sync 40, AppSupport 116), and the iOS
  Simulator application build passed. Logs: `/tmp/mop-sync-conflict-tests.log`
  and `/tmp/mop-sync-conflict-ios.log`. The physical conflict-handling failure
  remains unconfirmed; this does not claim that iPhone synchronization is fixed.
- Sync-resume follow-up: **321/321 affected tests passed** (Sync 40, UI 165,
  AppSupport 116). The user reported that Mac/iPad changes propagate while the
  iPhone neither uploads nor receives, with Refresh showing no error. Refresh
  previously refreshed only discovery/local projections. Unlock, foreground,
  remote hints and explicit Refresh now issue a coalesced, nonblocking sync wake
  separate from local reads. Repository notifications never generate this wake,
  avoiding a feedback loop. Failed wake requests retain local access and display
  a retry warning with Details; adapter failure categories are logged without
  record contents. Existing suspended adapters use their foreground recovery
  entry point instead of failing in start() first. Runtime and UI regression
  tests passed; log: `/tmp/mop-sync-resume-tests.log`. This identifies recovery
  gaps, not a confirmed diagnosis of the physical iPhone's underlying failure.
  Physical upload/download acceptance remains pending for this fix. Native iOS
  Simulator and macOS builds passed; logs: `/tmp/mop-sync-resume-ios.log` and
  `/tmp/mop-sync-resume-macos.log`.
- Persistent encrypted display catalog: **421/421 affected tests passed**
  (VaultNext 28, Sync 40, Core 47, CLI 27, UI 164, AppSupport 115). Restart tests
  with 1, 40 and 1,200 items return the complete list even with a display batch
  size of one, using at most two hardware unwraps during display opening. A single
  source change or damaged row needs at most one additional unwrap. Tests cover
  scope/device/row authentication, key damage, source/key CAS across reopened
  repositories, lock denial, unchanged outbox/sync requests and preserved visible
  search fields with concealed fields absent. Source record IDs/versions survive
  key-cache repair. Log: `/tmp/mop-persistent-catalog-final-tests.log`.
  Runtime test fixture cleanup emitted Core Data temporary-database I/O diagnostics;
  all assertions passed and the runner exited successfully. These software-device
  counts do not establish real Secure Enclave latency or mobile first-paint time.
  Native macOS and iOS Simulator builds passed; logs:
  `/tmp/mop-persistent-catalog-macos.log`, `/tmp/mop-persistent-catalog-ios.log`.
- Editor opening follow-up: **276/276 affected tests passed** (UI 164,
  AppSupport 112). The reported airplane-mode screenshot failed during
  `beginItemEditing`, before a save, with native LocalAuthentication -1004
  (interaction required). Editor hydration now passes the selected storage UUID
  to the exact-item local read path instead of falling back to a name/catalog
  scan. Native authentication failures in foreground operations lock the session
  and give explicit unlock guidance while retaining the original diagnostics.
  Regression coverage verifies the editor passes that identity and expired
  authorization clears protected UI and permits a fresh unlock. Log:
  `/tmp/mop-edit-offline-final-tests.log`. Real-device airplane-mode reproduction
  and Secure Enclave authorization reuse remain to be verified. Native iOS
  Simulator and macOS builds passed; logs: `/tmp/mop-edit-offline-ios.log` and
  `/tmp/mop-edit-offline-macos.log`.
- Connection-flow follow-up: **163/163 UI tests passed**. Delayed admission
  continues the original unlock intent, a second vault joins the authenticated
  view without locking the first, and manual lock cancels pending automatic
  opening. Progress tests cover persistent indication while local refreshes
  begin/end and clearing it after item readiness. Log:
  `/tmp/mop-connection-flow-final-tests.log`. Native macOS and iOS Simulator
  builds passed; logs: `/tmp/mop-connection-flow-macos.log` and
  `/tmp/mop-connection-flow-ios.log`.
- Initial-download presentation: **340/340 affected tests passed** (VaultNext 27,
  Sync 39, UI 162, AppSupport 112). Regression coverage verifies metadata-only
  download state, persistence across reopening the SQLite store, transition to
  key-wrapper waiting and eventual readiness, and notification-driven UI updates.
  Log: `/tmp/mop-download-status-final-tests.log`. The run also emitted Core Data
  I/O diagnostics for a runtime fixture's temporary database during cleanup;
  no test assertions failed and the runner exited successfully. macOS and iOS
  Simulator builds passed; logs: `/tmp/mop-download-status-macos.log` and
  `/tmp/mop-download-status-ios.log`.
- Automatic same-account connection: **413/413 affected tests passed** (CLI 27,
  Sync 39, Core 47, VaultNext 27, UI 161, AppSupport 112). Coverage includes
  scoped signed enrollment, metadata verification before trust installation,
  durable admission and lost-acknowledgement recovery, pending item wrappers,
  offline-edit membership catch-up, receipt supersession and discovery without
  duplicate vault creation. Final-source macOS and iOS Simulator builds passed.
  Logs: `/tmp/mop-enrollment-final-affected.log`,
  `/tmp/mop-enrollment-macos-final.log`, `/tmp/mop-enrollment-ios-final.log`.
  These checks do not establish real iCloud delivery or Secure Enclave behavior;
  physical enrollment acceptance was subsequently confirmed by the user above.
- Named-reference lookup follow-up: **401/401 affected tests passed**. A fresh
  service/session and reopened SQLite store require at most three key unwraps
  for a field read with either 1 or 40 items after catalog seeding. Coverage also
  includes cache tampering, replay of a stale authentic cache, rename/deletion,
  duplicate-name rejection, scope isolation, transactional revision checks and
  absence of new sync requests from cache writes. These software-device tests
  establish operation counts, not real Secure Enclave latency. Log:
  `/tmp/mop-name-index-affected.log`. The native macOS build passed; log:
  `/tmp/mop-name-index-macos-build.log`.
- Progressive opening: final affected run **397/397 passed**. Coverage includes
  partial first-batch delivery, exact-item reads before completion, complete
  inventory publication, selection/reveal preservation across unrelated batches,
  lock cancellation, concurrent edits and stale/bounded batch validation. macOS
  and iOS Simulator builds passed; the final post-await generation guard also
  compiled and passed in the final SwiftPM run after those builds. Logs:
  `/tmp/mop-progressive-final-affected.log`, `/tmp/mop-progressive-macos-build.log`,
  `/tmp/mop-progressive-ios-build.log`. Real-device first-paint timing remains to
  be measured with the user's large vault.
- Large-vault responsiveness follow-up: **394/394 affected tests passed**.
  Counting-device fixtures cover 1 and 40 items: cold visible catalog uses at
  most one unwrap per item plus vault metadata, warm catalog uses none, a single
  reveal uses at most two, and a one-item update does not reopen unchanged items.
  A suspended cloud-start fixture proves local inventory/registration do not wait
  on network setup. Catalog/reveal crypto runs off the caller executor, with
  cancellation and lock checks between items; no persistent key cache was added.
  Cold opening still requires one hardware unwrap per item and needs real-device
  timing confirmation. Final-source focused checks passed 11/11; macOS and
  iOS Simulator builds passed. Logs: `/tmp/mop-performance-affected.log`,
  `/tmp/mop-performance-final-focused.log`, `/tmp/mop-performance-macos-build.log`,
  `/tmp/mop-performance-ios-build.log`.
- Multi-vault source cutover: final affected run **392/392 passed** (Core 47,
  VaultNext 27, Sync 36, CLI 21, UI 159, AppSupport 102). Both native macOS and
  iOS Simulator Mop builds passed, including AutoFill. Tests cover automatic
  service-stream refresh/edit deferral, exact delivery receipts, postcommit lock
  outcomes, trash/name-reuse preservation, shared engine ownership, cross-process
  commissioning, reserved local-vault boundaries and bounded waits against
  uncooperative callbacks. Independent wire fixtures verify the documented backup
  framing/key encoding. Obsolete v7 engine tests were removed with their
  implementation; retained item fixtures construct logical archives/membership
  directly, without a legacy engine. No real CloudKit or hardware acceptance ran.
  Logs: `/tmp/mop-cutover-final-affected.log`, `/tmp/mop-cutover-macos-build.log`,
  `/tmp/mop-cutover-ios-build.log`.
- Initial foundation affected-target run: 390/390 tests passed (vault crypto, item sync,
  application service and UI model). This includes revision replay rejection,
  bounded upload selection, conflict-blocked export and immediate restored-vault
  selection.
- Initial foundation macOS and iOS Simulator application builds passed, including
  AutoFill. These builds precede selective edit/conflict additions.
- Selective edit/conflict stage: 404/404 affected tests passed, plus a new focused
  conflict preview/reveal test. Coverage includes unchanged ciphertext, explicit
  rekey, stale review rejection before decryption, receipt accuracy, automatic
  observation and clearing visible state on lock.
- Local bootstrap stage: 414/414 affected tests plus 1/1 portable CLI test passed.
  Both macOS and iOS Simulator application builds passed, including AutoFill.
  Tests cover pin-before-commit interruption/restart, source and scope mismatch,
  completed retry preserving later edits, same-source concurrent initialization,
  cached session lifetime, namespace isolation and actual mid-transaction rollback.
  A rollback fixture exposed duplicate sequence allocation inside a batch; the
  implementation now reserves an overflow-checked contiguous range. The exact
  postcommit lock race was reviewed but not deterministically injected.
- Cloud provisioning slice: 425/425 affected and portable CLI tests passed; macOS
  and iOS Simulator application builds passed. Fake transports cover lost
  acknowledgements, restart, missing commissioned zones, changed control records,
  stop/lock/account retirement, transient trust unavailability and exact publication
  gates. Native account namespace/lifetime tests use an isolated notification
  center. No real CloudKit calls, schema deployment or account operations were run.
- The broader suite run before the final revision/batching changes passed
  613/616 tests. Its three failures were subscription file-protection tests;
  an isolated Foundation probe reproduced `EPERM` for
  `.completeFileProtection` in this macOS environment. Product protection and
  security assertions were retained. A stale pre-existing UI message assertion
  was updated to the already-current product wording.
- These automated tests did not perform real CloudKit account operations,
  real-vault export, hardware acceptance, or release acceptance. Subsequent user
  backup/restore confirmation and preservation of the signed CLI are recorded
  separately above; they are not inferred from fixture test results.
