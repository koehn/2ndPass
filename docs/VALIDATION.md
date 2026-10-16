# Validation and release acceptance

2ndPass remains a development preview. Build success, software fixtures and simulator tests are distinct from physical Secure Enclave, live iCloud and release acceptance.

## Cleanup validation

See [current cleanup validation](CLEANUP-VALIDATION.md) for the removal work.
The dated observations below predate this cleanup and do not validate the changed
implementation. References to retired workflows describe historical checks only.

## Recorded physical checks

- October 3, 2026: the user confirmed portable backup/restore, large-vault responsiveness and CLI lookup acceptance, followed by automatic same-account enrollment acceptance.
- October 4, 2026: the user confirmed that an item created on iPhone reached Mac and iPad, a Mac edit reached both other devices, and an offline iPhone edit uploaded after reconnection without manual Refresh.

These observations cover the previous protocol preview and those scenarios only. They do not establish concurrent-edit resolution, cross-account sharing, revocation, recovery after device loss or complete remote backup inventory.

## Remaining release gates

- Concurrent same-item edits, explicit conflict resolution, interruption/restart and receipt supersession on physical devices.
- Repeated lock/reopen, relaunch and offline use of a large encrypted catalog; changed and damaged-row repair without data loss.
- Signed app/CLI/AutoFill installation, authentication, account changes, background delivery and protected-store unavailability across supported platforms.
- Independently verified backup completeness, fresh-identity restore and loss-of-account scenarios; device-local exclusions must remain explicit.
- Production CloudKit schema and provisioning validation using disposable vaults.
- Physical acceptance of device removal, permanent vault deletion and recovery. General document import, credential-account management and cross-account sharing remain unimplemented roadmap requirements.
- Accessibility and every UI flow, purchase/distribution acceptance, and independent cryptographic/security review.

The roadmap tracks these requirements. No automated result substitutes for an unperformed physical or release check.

## Recovery acceptance

Current automated recovery coverage is included in the cleanup validation. Live
CloudKit and Secure Enclave acceptance still requires activating recovery and
verifying recipient-grant coverage, making every original device unavailable,
recovering on a fresh same-account device, and reconnecting an original device
to verify reading, editing and synchronization. Exercise interruption, deferred
grant delivery and key rotation on both platforms. A destructive local reset
is not a substitute for these checks.

## Rotation interruption and password-health cache (2026-10-10)

Upload preparation now exits on Swift/CloudKit cancellation before retry bookkeeping or removal from the engine pending set. Authority barriers, final authority validation, and delivered-event checkpoint persistence remain intact. Password-health saves use live immutable password record identities for evidence freshness while retaining per-item parent-version checks; unrelated aggregate revision changes no longer discard valid evidence.

Focused tests passed for interrupted preparation (including a cancelled task), delivered-event persistence, and health-cache saves across unrelated edits versus real password replacement. The full elevated Swift suite passed all 671 tests (`/tmp/mop-interruption-full.log`); `git diff --check` passed. Signed-device rotation/enrollment confirmation remains a physical acceptance check.

## Interrupted DEBUG enrollment reset (2026-10-10)

Discovery resumes an existing reset manifest before inventory opens the revoked identity. Reset completion uses cloud-head readback authenticated against pinned membership history, without requiring a local operation delivery receipt first. Unknown heads and empty removal sets do not authorize cleanup; pending-edit checks and the cleanup lease remain in force. Focused reset/membership tests passed, including accepted removal readback, rejection of pre-removal or unpinned heads, and rejection of the removed device on unlock. Physical phone relaunch and fresh enrollment still require signed-device verification.

## Incremental sync status and inbox capacity (2026-10-14)

Sync health maintains a joined operation/inbox aggregate refreshed by persistent history, including incomplete receipts, orphan inbox rows, failure/kind counts, and oldest/latest dates. Only immutable snapshots leave the queue-confined cache. Capacity maintains an account-wide byte/count summary and overlays unsaved changes without scanning all retained records. The cross-process capacity boundary, rollback invalidation, authorization permits, and checkpoint transactions are unchanged.

Validation: all 106 sync tests passed; after reducing retained health-summary memory, 17 focused performance/capacity/checkpoint tests passed. Regressions cover external repository writes, deletion, duplicate staging, rollback, partial receipts, and checkpoint replay. `incrementalStatusAndCapacityBenchmark` compares the previous query shapes on the same store with warm projections: 100 changes, 16,000 operations and 5,000 inbox rows. The final local run measured health reads at 0.0275 s versus 1.1692 s, and capacity reads at 0.0150 s versus 0.1065 s. Persistent-history refresh is performed before timing either query; equality and bounded aggregate-update counts are asserted, while timing ratios are reported rather than asserted. Run with `swift test --disable-sandbox --filter JournalPerformanceTests` using the cache paths and permissions described in AGENTS.md.

These are local query benchmarks, not end-to-end iPad or iCloud speedups. Reprofile the signed iPad build against its existing backlog to measure the actual drain-rate improvement.

## Grant-request prerequisite recovery (2026-10-14)

Waiting grant requests now persist their observed item head and membership digest, plus any exact missing ancestor. Relevant changes re-enter normal signed-request verification; unrelated inbox progress does not retry them. Legacy key-state waits re-enter verification once to adopt this dependency representation. Missing or potentially stale heads get a durable targeted fetch, deduplicated per observed state. Missing ancestors use immutable version fetches. Both use bounded access scheduling alongside inbox processing. Fetched heads are atomically staged with fetch completion, without advancing engine checkpoints or treating reception as verification.

A generation mismatch alone never retires a request. Retirement requires the existing verified removed-device path or a signed successor chain from the current publishable head, followed by a transactional state/policy check and reconciliation of current recipient grants. Unknown cloud records and unproven generations remain pending; genuine verification failures remain failures.

Validation: 108 MopSync tests and 215 MopAppSupport tests passed with `swift test --disable-sandbox --filter 'MopSyncTests|MopAppSupportTests'` and the cache/permission settings above (`/tmp/mop-prereq-broad-final.log`). New regressions cover relevant versus unrelated changes, restart persistence, stale-head refresh, deduplicated fetches, missing ancestry, verified retirement versus unknown generations, excluded recipients, wrong record routes, unknown cloud records, checkpoint preservation, and bounded fetch/inbox scheduling. Live iCloud convergence of the iPad's existing backlog still requires a signed-device run.

## Missing-prerequisite recovery and blocked-operation details (2026-10-14)

Rotation and grant preparation now persist signed own-grant requests and an observation-scoped head refresh when local access is missing. Rotation persists exact ancestor fetches before waiting. Dependency availability is a scheduling hint only: normal authenticated inbox application and session/publication verification still gate access and writes. Durable engine checkpoints are untouched by prerequisite requests and manual refresh. Historical grants may be verified for recovery without permitting obsolete grants to be published.

Sync health maintains incremental blocked-work groups containing counts, oldest operation creation dates and effective retry deadlines, without retaining payloads or dependency identifiers in the diagnostic projection. The existing sync issue details show corrective steps and distinguish untimed prerequisite waits from scheduled retries. Explicit Refresh/Synchronize can rearm completed unchanged-head reads in one transaction; lifecycle, push and other background wakes cannot. Responses awaiting verification, quarantined work and server retry floors are preserved.

New regressions cover missing grants/ancestors across store reopening, request deduplication, malformed-record rejection, no readiness from reception alone, successful resumed rotation, unchanged checkpoints, manual retry floors, persisted/cleared health details, and manual versus background UI routing. Existing checkpoint, security, search and selection tests remain in the full suite. Full suite: 719 tests passed (`/tmp/mop-prerequisite-final.log`); the final batched-refresh change passed 113 additional sync and focused recovery/reporting/UI tests (`/tmp/mop-prerequisite-batch-final.log`). Physical-device CloudKit convergence remains a separate validation step; no production iCloud data, device enrollment, local app data or key hierarchy was changed.

### Reset completion pause (2026-10-14)

After a successful debug enrollment reset, the app locks and shows a force-quit
alert. It does not discover vaults or open enrollment. Discovery, unlock,
reconnect, and refresh remain blocked in that process even after dismissing the
alert or returning to the foreground. Force quit; keep the remaining devices
online and unlocked, using Vault → Force reconcile on Mac, and reopen the reset
device only after the remaining devices have finished re-syncing. This pause
does not claim to verify convergence on those devices. Failed resets retain
their existing enrollment and error handling.

### Bounded rotation readback regression

Run `swift test --disable-sandbox --filter 'rotationBatch|previewRotationReadback'`
with the module-cache environment above. Cases cover 895/1,000 operations,
success/throttling, enrollment fairness, retry floors, partial responses,
missing accepted heads, invalid payloads, account invalidation during fetch
and between items, and unchanged checkpoints. Run
`python3 scripts/test_audit_cloud_sync.py` for offline timing-parser checks.
The full suite retains interrupted rotation recovery and signature/authority
tests. These are software tests, not CloudKit/Secure Enclave measurements.

Validation result: full Swift suite passed 723 tests. After the final runtime
error-routing adjustment, all 6 targeted tests passed (including four scheduler
parameter cases); both Python parser tests passed. The repeated local 895-item
benchmark recorded 18.45 s for rotation and 2.60 s for new-device grants, excluding
CloudKit and Secure Enclave. No physical-device reset or production data change
was performed.

## Enrollment grant-request suppression (2026-10-15)

Grant preparation is indexed per item and recipient on every device. Previously,
a newly admitted device immediately requested its own missing grant, even while
existing devices were preparing those grants automatically. Initial enrollment
now waits up to 120 seconds from each durable operation's creation before
publishing repair requests or fetching heads. Verified grant arrival releases
the wait early; restart, foreground and unlock do not extend or bypass its
deadline. Existing devices with source grants still prepare grants immediately.
The enrollment marker is a scheduling hint, never evidence of authorization or
completion. Grants still missing at the deadline use the existing repair path.

Authenticated echoes addressed to the current session's recipient complete
without starting another head fetch. Concurrent signing of the same deterministic
grant request reuses the authenticated durable winner, while mismatched payloads
are rejected. The wire format is unchanged.

Regression coverage includes automatic grant arrival, timed repair, reopening
the repository, repeated wakes, deduplicated requests and fetches, own-request
echoes, concurrent signing and payload mismatch rejection. Physical-device
iCloud enrollment remains a separate validation step.

Validation: all 737 Swift tests passed (`/tmp/mop-enrollment-grant-full-tests.log`),
and the unsigned generic iOS build succeeded (`/tmp/mop-grant-repair-ios.log`).
