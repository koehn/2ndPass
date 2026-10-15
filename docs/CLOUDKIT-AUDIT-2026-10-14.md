# CloudKit remove/re-add audit — 2026-10-14

Baseline: `3a03d54` (following `c79a622` and `193afcd`). The working tree was clean at audit start. No device reset, production CloudKit request, local app-data deletion, or key-hierarchy change was performed. Tests use temporary stores and software keys. This is a source audit plus local measurements, **not a demonstrated three-device iCloud convergence result**.

## Assessment

The implementation has strong local durability and explicit cryptographic boundaries. It does not yet establish bounded cross-device redundant work or an actionable outcome for every indefinitely blocked dependency. Additive enrollment avoids security rotations; device removal does require them. Independent devices can still generate distinct grants for identical access and race to rotate the same content. Local synchronization leases are not distributed locks.

Two localized fixes accompany this audit:

1. `DurableSyncCoordinator.wake`: retrying rotations/inbox applications now count toward the 16-operation bulk yield. A carried foreground/unlock reset hint cannot immediately reset the same bulk retry again in that drain. The existing success-only budget could leave access work behind all 895 failing rotations. Regression covers successful and failing backlogs, arrival during an in-flight handler, durable outcomes, exactly one attempt per operation, and a foreground hint with an injected clock.
2. `EncryptedItemRepository.contentPublications`: reserve 16 of the 100 candidate slots for grants when eligible grant work exists. Previously 895 immutable versions plus 895 heads could occupy content-only pages before any grants were selected. This is candidate fairness, not a wall-clock delivery guarantee: coordination records still precede content, the adapter has its own byte limit, and server scheduling/throttling can delay submission. No signature, membership, publication barrier, acknowledgement, or checkpoint checks were removed.

## Lifecycle and evidence

| Phase | Source and behavior | Remaining concern |
|---|---|---|
| Removal | `NativeItemVaultServiceBackend.manage(.removeDevice)` preserves the removed-device set, prepares a signed membership successor, enqueues durable work, and reports rotation as incomplete. `JournaledContentMembership` publishes/reconciles membership under authority checks. | The removal UI acknowledgement means intent saved, not all 895 keys revoked. An offline removed phone retains previously obtained plaintext/keys. |
| Authority propagation | `ItemVaultSyncRuntime.changedMembership`, `GrantBackedMembershipInbox`, `GrantBackedContentStorage.derivedMembership` authenticate history and install the recipient policy. An invalid content-key path changes key authority. `ContentStore.reconcileGrantRequirements` enqueues deterministic per-item rotation IDs. | Each remaining device does this independently. No cloud-wide designated rotator. Metadata is another encrypted item. |
| Rotation | `CloudKitSyncAdapter.performContentRotation` checks whether already satisfied, cancels engine operations inside a bounded barrier, reads back the exact mutable head, stages/applies it, then invokes the session. `ContentRotationReadback` treats disappearance of an accepted head as a conflict, not permission to resurrect it. `commitContentRotation` atomically commits ciphertext, randomized grants, outbox and supersession. | Up to one direct head read per attempted item per device; 895 cancellation/readback barriers per survivor in an overlapping run. A readback prevents unnecessary work when another rotation is already installed, but cannot elect a winner before two simultaneous readbacks. Lost acknowledgements and conflicts require these checks. |
| Device reset versus removal | The DEBUG `debugResetEnrollment` persists a manifest before publishing self-removal, verifies signed cloud heads, waits up to 30 seconds with 2-second readback polling, then stops runtime, obtains the cleanup lease, rechecks pending work and clears enrollment storage/keys. Relaunch resumes the manifest. | This is destructive local cleanup, unlike ordinary removal. Never use it as an audit shortcut. Its full-store clearing also discards the local sync state; a fresh enrollment may legitimately need a full fetch. No reset was executed here. |
| Re-enrollment | `ItemDeviceEnrollment`, `NativeItemVaultServiceBackend.progressEnrollment`, and `GrantBackedContentSession.prepareEnrollment` retain signed requests/approvals; approval reuse is per request. Membership commitment is a prerequisite for a new approval; an existing admitted identity uses reconnect. A new identity is required after removal. | Both owners may approve concurrently; membership reconciliation is needed. Additive admission keeps key authority unchanged. Re-enrollment while removal rotation is unfinished inherits outstanding rotations; that is not a second rotation caused by admission. |
| Grants | Policy reconciliation indexes missing `(item, key generation, recipient)` work. `contentGrantPreparation` performs point reads; a valid source grant unwraps the key and a fresh grant is signed/committed. Exact prepared bytes survive retries. `ContentKeyGrant.context` includes source version, membership and issuer. | Mac and iPad can generate different valid record addresses for the same recipient/key generation. Local deterministic operation IDs do not deduplicate independent issuers. Receiving a peer's grant before preparation avoids work, but grants already generated remain separate records. |
| Requests/prerequisites | `GrantBackedCoordinationInbox` verifies signed routing/recipient/membership. Removed authors' old requests are retired only after historical verification. `GrantRequestPrerequisites` requests exact missing ancestors or one mutable-head refresh per observed state, and retires obsolete generations only after verifying ancestry. | A successful refresh returning the same head, with an unproven requested generation, leaves a durable wait until head/history changes. No timer or actionable per-item explanation is guaranteed for that wait. Never infer deletion/obsolescence just from an unknown record. |
| Inbox | `receiveBatch` materializes CKAssets, chunks at 200 records/8 MiB, and persists before checkpoint advancement. Public verification does not require device secrets. Missing ancestry/membership gets durable prerequisite work. Conflicting content may require an unlocked comparison session. | Head and immutable version each contain ciphertext; historical grants/versions also get fetched. A grant arriving before its source can generate a targeted version read. These are legitimate ordering dependencies, but overlap with bulk fetch may duplicate reads. |
| Restart | Engine serialization is loaded from its namespaced durable checkpoint. An unreadable checkpoint aborts startup rather than silently starting over. Active data events gate checkpoint saves; failure suspends transport. The durable journal resumes pending application and publication. | Checkpoints bound replay; they do not provide exactly-once network delivery. A crash after staging but before checkpoint persistence can replay a page. `replayAfterCompletedIncomingRearmsDurableApplication` deliberately supports replay. Server token invalidation, a new store, or explicit reset can cause larger fetches. |

Relevant recent fixes in `3a03d54`: concurrent reconciliation alongside local work; 16:16 access/inbox scheduling; publication registration outcome coalescing; retry deadline cleanup on transport handoff; remote rotation retirement; obsolete-request retirement; targeted head/ancestor recovery; incremental journal/health/capacity projections; shared session registration and display continuity. `c79a622` enlarged receive commit chunks and introduced device unenrollment. These improve local behavior but are not evidence of cross-device delivery latency.

## Record and byte accounting

Use **N = 895 user items** below. Add one for vault metadata if present: N = 896. Include any tombstones/other retained content separately. Let q be 1 when offline recovery is configured, else 0; C0/C1 are average serialized pre-/post-rotation content bytes; G0/G1/G2 are serialized old/rotation/re-enrollment grant bytes. Payloads include the application's encryption/signature/encoding overhead, but exclude CloudKit protocol, system fields, indexes and TLS. Counts are records, **not network requests**. The adapter selects up to 100 records and a 16 MiB payload budget; CKSyncEngine owns actual request packaging and retries.

The following is the ideal sequential case: all three devices initially converged, Mac removes iPhone, rotation finishes before the new phone identity joins, Mac is the sole producer, and there are no concurrent edits. Existing iPad keeps its checkpoint; a fresh iPhone has none. Coordination/membership records are additional to these per-item costs.

| Device / phase | Expected content reads/downloads | Expected content writes | Logical payload bytes |
|---|---:|---:|---|
| Mac / removal rotation | N exact head readbacks; change-feed echoes possible | N versions + N heads + (2+q)N grants = (4+q)N; 3,580 at q=0 | Reads N*C0; writes N*(2*C1+(2+q)*G1) |
| iPad / removal rotation | (4+q)N changed records if it only receives Mac's work | 0 needed | N*(2*C1+(2+q)*G1) received |
| removed iPhone / removal | Delivery depends on runtime state; same Apple account can still access ciphertext | 0 authorized new content/grants | Do not promise zero transport reads or remote erasure |
| Mac / settled re-enrollment | Request/ack and membership traffic; no per-item cloud read needed if local prerequisites present | N new-recipient grants = 895; **0 content rotations** | N*G2 sent |
| iPad / settled re-enrollment | N new grants plus membership/coordination | 0 needed | N*G2 received |
| fresh iPhone / full content-zone download | With exactly one original version and one rotation retained: (9+2q)N records = 8,055 at q=0 | No content writes required; request/ack, possibly per-item missing-grant requests | N*(C0+2*C1+(3+q)*G0+(2+q)*G1+G2) received |
| Any device / ordinary restart | Resume checkpoint + durable inbox/outbox; no intentional full refetch | Retry exact undelivered records only | Last uncheckpointed page/failed batch may repeat; not all N by design |

The fresh-download count is one current head, two immutable versions, three original device grants, two surviving-device rotation grants, one new-phone grant, and q recovery grants for each key generation. Actual retained histories, branches, edits, recovery grants and issuer duplicates change this count. An existing phone reusing a valid store/checkpoint instead downloads deltas; do not apply the fresh-store estimate to it.

Removal membership publication and admission membership publication each need signed head/history transport; request, approval, acknowledgement, cleanup and optional grant requests add control records and reads. Their exact count is conditional (reconnect, competing approvals, retries, persisted receipts), not a fixed per-item factor. In a missing-own-grant case up to N signed grant requests may be prepared per recipient/key generation. DEBUG self-reset adds periodic membership-head readbacks per vault until verification/deadline. Inventory/trust discovery and membership recovery also add reads. Capture these separately rather than hiding them in ciphertext totals.

**Redundant scenarios:**

- Two survivors racing all rotations may both perform N readbacks and prepare N independent rotations. Work can approach twice the ideal producer crypto/payload attempt count before CAS/reconciliation; immutable branches and grants can survive even when only one head wins. This is an overlap estimate, not a measured upper bound on arbitrary retries.
- Two owners granting to the new phone can produce 2N grants: N useful coverage, N redundant coverage (and corresponding downloads on subscribers). The harness verifies distinct valid identifiers for two issuers. Admission history/source-version changes can create further addresses; there is no universal fixed bound across repeated membership changes.
- A signed same-generation grant already stored suppresses local preparation. Replaying completed preparation or rotation does not produce new random bytes. Grant-only admission leaves item revisions unchanged.
- Historical versions and nonrecipient grants transferred in a full-zone fetch are expected under this schema, though they are overhead relative to the new phone's minimum usable snapshot. They must not be called retry duplication.
- Direct prerequisite reads overlapping change-feed delivery, repeated rotation readbacks, failed submissions and self-echoes are additional transport work. Only signed-device logs/server metrics can quantify them.

## Security and remaining liveness risks

The private database is an Apple-account boundary; application device revocation is enforced by signed membership and key rotation, not per-device CloudKit ACLs. Revocation cannot retract already disclosed plaintext or old item keys. After removal, future ciphertext must use new item keys excluding the removed device; the completion criterion must cover every item, including metadata. A phone with the same Apple ID may download ciphertext it cannot decrypt. Multiple-user/cross-account permissions are outside this single-account content policy and are not validated by these tests.

Signatures bind vault, item, generation, recipient, issuer and membership; trust comes from independent pins. Public inbox verification precedes usable access. Preparation and publication revalidate authority; lease/permit checks guard writes and session invalidation. The audit does not relax any of these boundaries. Stable hashed diagnostic tokens reveal correlation and timing; retain logs as sensitive metadata even though they contain no payloads, names or keys.

Priority remediation:

| Priority | Finding | Proposed next action / acceptance |
|---|---|---|
| P1 | Cross-device duplicate rotation/grant production; no distributed ownership | Review deterministic preferred producer with bounded takeover and freshness rules, or another coordination protocol. Must work when the preferred device is locked/offline and preserve CAS/readback. Measure duplicate addresses and crypto before implementing. Do not simply suppress all nonpreferred devices. |
| P1 | Missing prerequisites can wait indefinitely without a useful user explanation | Add per-operation dependency age, exact reason, last fetch outcome, next retry and suggested action. Distinguish unknown cloud record from invalid signature. Unknown-generation waits must surface “no verified successor” with an explicit refresh/recovery route. Preserve evidence and never auto-retire unverifiable requests. |
| P1 | Rotation session's missing source grant or missing unpublished ancestor returns `.retry(.dependency)` without explicitly scheduling its own repair in that branch | Route these through existing durable exact-version/own-grant prerequisite machinery with tests for isolated missing prerequisites and interrupted rotation. Some normal inbox paths already recover them; source inspection does not establish recovery for every entry path. |
| P1 | Candidate grant fairness is not end-to-end fairness | Fixes here bound failed bulk slices and reserve grant candidates. Validate adapter byte-budget truncation, all-control pages and metadata access. If still slow, design byte-aware interleaving without causing grant-before-source fetch storms. Network handlers still serialize and can wait an unbounded network duration; 16 operations is not 16 milliseconds. |
| P2 | Dependency-completion wakes can accelerate many `.retry(.dependency)` operations; explicit foreground/network-restored wakes reset backoff | Persist specific dependencies where possible; measure retries per prerequisite change. Keep CK server retry floors and CKSyncEngine ownership. Current exponential retry caps at 300 s with jitter, while server retry-after can exceed it. |
| P2 | Repeated cancellation/readback per rotated item | Investigate bounded multi-item barriers/readback batching with exact accepted-head evidence. Never remove lost-ack readback or compare-and-swap to save requests. |
| P2 | Status conflates phases | Enrollment “Device connected” means membership, not all item access. Catalog strings distinguish downloading and waiting and count items ready; there is no explicit verification backlog phase. Add downloaded/staged, verified, grant-covered and projected/usable counts, plus the first blocked reason. A denominator based on an enrollment hint may grow. |
| P2 | Full fetch includes retained ciphertext versions and all issuer/recipient grants | Measure retained records by kind/epoch and evaluate authenticated retention/snapshot approaches. Never garbage-collect recovery/conflict ancestry merely to match the ideal count. |

Local usability is materially improved by `ItemVaultSessionRegistry`, `inheritDisplayContinuity`, scoped catalog progress and incremental search updates. `changedMembership` keeps a still-authorized session until a replacement is ready, but locks it on removal or authentication failure; uninterrupted access is appropriately conditional on continued authorization. Existing AppModel/search tests cover selection preservation, incremental projection and status behavior. Software tests do not prove frame latency, Secure Enclave prompts, memory pressure or background behavior on an iPhone. Removed-device access is not part of the uninterrupted-usability promise.

## Architecture options for review only

| Design | Performance | Security/revocation | Migration and complexity |
|---|---|---|---|
| Current per-item device grants | Admission O(N) wraps/signatures/records per issuer; removal O(N) ciphertext rotation plus O(N*recipients) grants | Fine-grained item keys; each grant bound to signed content/membership. Removed device retains old knowledge. Independent issuers duplicate coverage. | Already deployed; improve scheduling, ownership and explanations first. |
| Vault epoch key wraps item keys; device grants wrap epoch key | Admission can be O(devices) epoch grants rather than N device grants; still needs item envelopes/download/verification. Epoch distribution reduces per-recipient grant records. | An epoch key exposes every item key wrapped under it. **Rewrapping unchanged item keys under a new epoch does not revoke a device that cached the old epoch/wrappings.** Equivalent future-content confidentiality requires rotating compromised item keys/content, or a carefully specified lazy rotation on writes with weaker immediate revocation semantics. | New signed epoch descriptors, rollback protection, membership binding, atomic activation, old-epoch retention and recovery design. Dual-format readers and resumable per-item migration; mixed-version writers must be gated. Security review required before implementation. |
| Per-item keys retained, with batched grant bundles or preferred producer | Reduce record/request overhead or duplicate work without changing key scope | Must authenticate each binding, handle partial bundles and preserve per-item revocation/receipt semantics. Preferred producer requires failover without permanently withholding access. | Smaller conceptual change than a vault hierarchy, but new record sizes, failure granularity, versioning and recovery rules still need review. |

Recommendation: first establish measured bounded work and reliable blocked-operation recovery under the existing key model. Consider epoch keys only if the cost evidence justifies the broader compromise scope and migration protocol. No architectural change is implemented by this audit.

## Reproduction, measurements and diagnostics

Run from the repository with the permissions described in `AGENTS.md` (no production app launch):

```sh
CLANG_MODULE_CACHE_PATH=/tmp/mop-clang-cache \
SWIFTPM_MODULECACHE_OVERRIDE=/tmp/mop-swift-cache \
swift test --disable-sandbox --filter GrantGenerationPerformanceTests

CLANG_MODULE_CACHE_PATH=/tmp/mop-clang-cache \
SWIFTPM_MODULECACHE_OVERRIDE=/tmp/mop-swift-cache \
swift test --disable-sandbox --filter 'MopSyncTests|MopAppSupportTests|AppModelTests|ItemSearchIndexTests'
```

Measured on this host, final relevant run: **108 sync + 216 app-support + 169 AppModel/search tests passed (493 total)**. The software benchmark reports:

| Measurement | Result | Boundary |
|---|---:|---|
| 895 removal rotations, including reopening the store after 447 | 18.633 s | Software crypto/local journal; excludes cloud readback, transport, Secure Enclave and UI |
| Projected current rotation publications | 3,580 records; 5,241,120 payload bytes | 895 heads + 895 versions + 1,790 grants, 1 KiB secret fixture, no metadata/recovery recipient; generated actual serialized payloads, not uploaded traffic |
| 895 grants for new phone identity | 2.668 s; 665,880 payload bytes | Actual local signing/wrapping; 744 bytes/grant for this fixture |
| Re-enrollment rotation count | 0 | Key authority unchanged; all 895 revisions unchanged by grants |
| Restart and replay | 448 rotations remained after reopening; replay changed no item revisions; grant replay added 0 signatures | Reopening a durable store, not killing a physical app or emulating CKSyncEngine |
| Usable new-phone access | 895/895 secrets opened | Software key provider, same repository; not a three-repository transport simulation |
| Cross-issuer duplication | Two valid grant identifiers for one identical recipient/generation | Demonstrates possibility; does not measure the live frequency over all items |
| Existing grant scaling fixture | 100: 0.359 s; 500: 1.436 s; 1,000: 2.728 s | 4 preparation rows/item, no vault scan, one unwrap/signature/item; mixed 1/64 KiB secrets |
| Upload fairness | First full page contains 84 content candidates and 16 grants | 100-record selector; not server delivery ordering |

The initial audit harness incorrectly queried one bounded upload page as the whole outbox; that run failed its accounting assertions and was corrected. All final measurements above come from the passing run. Test output includes Core Data diagnostics from temporary-store failure/teardown cases; the process exited successfully and all listed test groups passed. Raw logs for this session: `/tmp/mop-cloud-audit-sync.log`, `/tmp/mop-cloud-audit-benchmark.log` (initial failed harness), `/tmp/mop-cloud-audit-final.log` (passing final run). Temporary logs are not durable deliverables; the table and harness are committed-file artifacts.

Added diagnostics reuse `AccessSyncTrace` and log only counts, kinds and hashed identifiers: direct-fetch attempts/returns, rotation readback attempts/materialized bytes, successfully persisted checkpoint size, staged payload/system-field bytes, and submitted batch/record payload bytes. “Submitted” means handed to CKSyncEngine, **not** confirmed by the server; existing `record saved by cloud`/failure events distinguish outcomes. Checkpoint events are local storage writes, not CloudKit writes. `record staged locally` is a successful reception event, not necessarily a novel record. Trace events can be lost by log retention; counts are lower bounds unless capture completeness is established.

Export non-overlapping CloudSync log intervals from Console/Xcode per device and phase, then:

```sh
python3 scripts/audit-cloud-sync.py \
  mac:rotation:/tmp/mac-rotation.log \
  ipad:rotation:/tmp/ipad-rotation.log \
  iphone:enrollment:/tmp/iphone-enrollment.log > /tmp/cloud-audit-counts.json
```

The reader makes no network calls. It reports event counts, distinct record addresses, payload bytes and additional grant addresses for identical item/generation/recipient within each capture. To detect duplicates across senders, additionally combine the Mac/iPad enrollment intervals into a separate aggregate capture; do not add aggregate totals back to device totals. Repeated mutable-head addresses can represent legitimate updates, not redundant work. Membership versions, direct reads, staging and batch submission describe different stages of the same work: **do not sum stage totals as wire bytes**. Use CloudKit/server instrumentation and a controlled network capture to establish request counts, retries and actual transport bytes. The app trace does not instrument every provisioning/history/control request.

## Acceptance gates and concrete three-device procedure

These are proposed release gates, not claims already met. Use a dedicated development-container fixture/account and retain the existing production installation. Obtain explicit authorization before any physical-device membership removal/reset, clearing local state, or cloud mutation. This document is a procedure, not authorization to execute it. Do not simulate recovery by deleting databases or Keychain entries.

1. **Establish the fixture.** On signed Mac/iPad/iPhone builds of the same revision, create a disposable vault with exactly 895 deterministic fake items plus metadata. Include unique searchable names, mixed small/large fields, an attachment, and an offline recovery recipient in a separate run. Record build/container/environment, OS/hardware, account equality, record-kind counts and serialized payload totals. Converge and verify every item's ID, revision and plaintext digest through the app; keep plaintext test data out of diagnostic logs. Export a backup of the disposable fixture. Record baseline checkpoints and empty actionable queues.
2. **Capture baseline usability.** Keep a selected item open on Mac and iPad. Search, change selection, and edit one designated test item. Confirm durable save, selection retention and that unrelated search results remain available. Record main-thread stalls/search latency before sync; proposed p95 search/selection target under 200 ms, no blank list/selection reset, no lost edits. These latency targets are provisional until device baselines exist.
3. **Sequential removal.** With explicit test authorization, remove the phone using ordinary device removal on Mac. Keep iPad open/unlocked. Capture removal commitment separately from key rotation completion. Verify the removed phone cannot publish new authorized changes or decrypt post-removal generations. Verify all 896 encrypted records reach the removal key authority, retain valid recovery access if configured, and no removed-recipient grant exists for any new generation. Do not equate a removal toast with completion.
4. **Measure one producer versus two.** Repeat on separately authorized disposable fixtures with iPad offline during rotation, then with both survivors online/unlocked, and then with the Mac going offline midway. Count rotations, direct readbacks, versions, grant addresses, attempted/confirmed writes, conflicts and bytes per device. An ideal sole-producer run has one rotation/item, `(4+q)N` content writes and N readbacks. Target no redundant grants in the sequential case. For two producers, document a provisional ceiling of two preparations per item/recipient in a stable epoch and no third generation/issuer retry cascade; a stricter target of <=5% redundant payload requires ownership changes and is **not currently guaranteed**. Every conflict must resolve or remain visibly actionable, never silently disappear.
5. **Fresh enrollment and overlap.** Use the supported re-enrollment path with a new device identity; if the build requires a DEBUG local reset, obtain separate authorization for that disposable installation's cleanup first. Test once after rotation finishes and once during bulk rotation. Keep one existing device unlocked. Measure request received → membership committed → approval received → metadata usable → first item usable → 895 items usable. Under healthy foreground networking, propose membership/approval within 30 s and first usable access within 60 s; investigate failures with server throttles recorded separately. Locally, newly eligible access work must run within 16 completed/retrying bulk handlers, access/inbox must alternate in bounded slices, and grants must appear in a full candidate page while content remains. No additional rotation authority may be created solely by admission.
6. **Interrupt at durable boundaries.** In separate disposable runs terminate/relaunch the app after request preparation, after membership cloud commit before acknowledgement, after roughly 447 rotations, after grant preparation before send, and after inbox staging before verification. Use supported debugger/test injection to target these boundaries; do not corrupt stores. Confirm the checkpoint loads, pending counts resume, prepared record bytes/identities are reused and completed local crypto is not replayed. A duplicate uncheckpointed page is acceptable; an unexplained full 895-item refetch on every ordinary restart is not. Also relaunch after the UI previously timed out. Check no task remains “running” solely because the original process disappeared.
7. **Exercise dependencies and failures.** Delay grant/head/history delivery using a test transport or controlled device connectivity; deliver grants before their source versions; lock the sender and receiver independently; disconnect/reconnect networking. Include unknown record, account permission failure, quota/throttle and malformed-signature fixtures only through test infrastructure. Verify targeted prerequisite operations, persisted retry deadlines (including server retry-after), no exponential duplication of requests, inbox capacity pause/resume and preserved checkpoint. A missing dependency that makes no progress must show its reason and an actionable step within 60 s of detection; this gate is not fully met today. Do not forge or alter production CloudKit records for fault injection.
8. **Verify convergence and ongoing usability.** On both still-authorized devices continuously search/select/read/edit while downloading and projecting. Enrollment, downloading, public verification, grant availability and usable projection must be distinguishable; 100% ready requires actual usable access, not just membership. After the network and authorization recover, propose all 895 items plus metadata converge within 5 minutes for the small fixture under unthrottled foreground conditions. Compare accepted item revisions/content digests and current membership on all three devices, not issuer-specific grant equality. All operations must be completed, transport-owned with observable pending delivery, scheduled with a deadline, or blocked with a specific corrective action. Repeat with suspension/background and large payloads to establish separate OS-constrained budgets.

Do not certify Secure Enclave behavior, iCloud propagation, background execution or cross-account permissions from the local results. Retain the device-phase count sheets, timings, checkpoint evidence, blocked-operation explanations and final data comparisons with the release validation record.

## Follow-up: prerequisite recovery and blocked-work reporting

Implemented after the audit:

- Rotation with a missing source grant now prepares the same durable signed own-grant request used by grant preparation, plus a head refresh deduplicated by observed version/membership. It waits for a verified grant, changed item version, or changed trusted membership instead of retrying on unrelated store events. Another survivor can satisfy the wait by rotating the item; the waiting device still revalidates normal authority before doing any work.
- Missing rotation ancestors create durable exact-version fetch operations before the rotation enters a dependency wait. A crash between enqueuing the fetch and persisting the wait is safe: the next attempt finds the same deterministic fetch. Receipt alone never releases the wait; only the verified content archive does.
- Explicit Refresh/Synchronize can requeue a completed unchanged-head read for a still-waiting observation. Lifecycle/push/background synchronization does not rearm it. Pending verification prevents redundant refetching; transport retry floors and quarantined fetches are not reset. This supplies a deliberate recovery action for requests whose generation still has no verified matching history; it does not treat unknown records as obsolete.
- Incremental sync health now includes payload-free blocked-work groups, counts, oldest operation creation dates, and the earliest effective retry deadline per group. UI sync details explain missing access, content, membership, unproven history, transport, authorization and other failures with corrective steps. Dates are explicitly operation creation times, not invented “blocked since” or progress times. Completed operations leave the groups automatically. No item titles, payloads, dependency identifiers or keys are exposed.

Regression coverage includes reopening the store while awaiting a grant/ancestor, exact request reuse, malformed prerequisite rejection, staged-but-unverified data remaining blocked, resumed rotation after authenticated application, unchanged engine checkpoints, manual refresh without publication/verification shortcuts, server-deadline preservation, persisted health summaries, and user-refresh versus background-wake routing. Test fixtures remove a synthetic archived parent to exercise recovery; production data is never modified by these tests.

These changes address the audit's local prerequisite/reporting gaps. They do not supply distributed rotation ownership, guarantee that an offline peer or permanently missing cloud record becomes available, or implement a new key hierarchy. Such cases remain visible with a recovery action rather than being silently declared complete.

## Bounded removal readbacks and latency diagnostics (follow-up)

The prior path serialized each rotation through engine-wide cancellation, an
exact head read, verified application, local rotation, and upload registration.
Its direct adapter/readback path invoked account validation five times per
successful item; each native validation awaits account status and user record
ID. These are API invocations, not proven network requests. At an assumed
500 ms per serialized head fetch, 1,000 fetches alone take 500 seconds. This is
a latency model, not a measurement of the reported ten-minute device run.

The coordinator now passes at most 16 consecutive, already-eligible rotations
to a batch handler, respecting dependencies and server retry gates. The adapter
skips independently satisfied rotations, owns one cancellation barrier, and
fetches the remaining exact heads with CKDatabase.records(for:). Each head
still uses ContentRotationReadback: exact binding checks, durable staging,
authenticated application, missing-accepted-head conflict protection,
account/lease checks, and existing atomic local rotation/outbox commits.
The adapter then releases the barrier and registers uploads. No checkpoint is
advanced by batch fetching. Keys, grants and record formats are unchanged.

Results are matched by full CKRecord.ID. An omitted result is a transport
failure, never proof of absence. Per-record errors retain server retry floors;
malformed/unverified records cannot authorize rotation. Account invalidation
after fetching prevents effects; invalidation between items retains the
completed prefix and defers the rest. After interruption, durable rotation
state and outbox records remain authoritative; a batch is not a receipt.

The fairness boundary remains 16 attempted bulk items (including blocked
outcomes), then pending enrollment/membership wakes can run. A network wait
already in progress cannot be preempted. Publication preparation is blocked
during the barrier: batching trades a longer individual barrier for fewer
cancellations. Signed-device testing must verify upload progress between
batches and control-traffic latency during large asset downloads. CKAssets
are materialized one item at a time under existing limits; grouped downloads
can still increase temporary asset storage and inline-record memory.

### Evidence and expected costs

The scheduler regression covers 895 and 1,000 eligible rotations with success
and throttled outcomes: 56 and 63 groups respectively, enrollment after the
first 16 items, and no bypass of a separately throttled operation. An isolated
readback test combines valid, disappeared, omitted, throttled, and corrupt
responses. Other tests invalidate authority during fetch and between items.
Existing lost-ack, restart, checkpoint, authority, conflict and rotation tests
remain in the suite.

For a stable sole-producer 1,000-item backlog, the ideal adapter path drops
from 1,000 single-record fetch calls/cancellations/registrations to 63 groups.
It still reads 1,000 records and produces the same ciphertext/grant records.
This does not promise 63 wire requests: CloudKit owns packaging, throttling,
retries and asset downloads. Account validation remains around every item's
verification/rotation, with shared batch boundary checks; no time-based
account cache or relaxed write authorization was introduced. Independent
producers can still duplicate work.

### Timing capture and interpretation

AccessSyncTrace now records monotonic milliseconds for account validation,
engine cancellation, batch fetch, verified application, local work, upload
registration and whole-batch time. A bounded in-memory map also samples
latest record-address submission to cloud acknowledgement. This is not
durable queue age or exactly matched immutable-version latency; restart and
map eviction can omit samples. The parser reports count, total, nearest-rank
p50/p95 and maximum per stage. Nested timings overlap: do not add them
together as wall time.

Run the three-device procedure on an explicitly authorized disposable fixture,
first with one producer, then two. Compare cancellation counts, batch sizes,
timings, confirmed publications, retries, duplicate rotations and final
accepted versions. Measure removal commitment to final rotation publication
and peer verification separately. No physical-device speedup is measured yet.

Deferred for architectural review: preferred-producer election/takeover;
account-check coalescing/caching with immediate invalidation guarantees;
vault epoch/key hierarchy changes. None is implemented here.

