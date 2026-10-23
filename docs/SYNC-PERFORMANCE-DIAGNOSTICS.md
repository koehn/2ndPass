# Diagnosing item availability

“Items ready” counts locally projected, decrypted catalog items, not downloaded
bytes. Encrypted records may be local while membership or recipient grants are
still unavailable. Devices exchange records through CloudKit.

Capture the `com.koehn.mop` subsystem, `CloudSync` category on both devices over
the same interval. On the Mac:

```sh
log stream --style compact --level info --predicate 'subsystem == "com.koehn.mop" AND category == "CloudSync"'
```

Useful `Access trace` events:

- `operation handled`: elapsed milliseconds, operation kind and outcome. Slow
  `prepareGrant` indicates local preparation; slow fetch operations indicate
  transport waits. Waiting/retry outcomes identify dependency or failure classes.
- `grant committed locally`: prepared access awaiting publication.
- `record saved by cloud` and `publication acknowledgment latency`: cloud upload
  completion and time from submission. Completion does not imply peer receipt.
- `grant applied`: recipient-side receipt and application.
- `catalog projection`: attempted, ready, total, waiting, pending and elapsed
  milliseconds. Waiting means access prerequisites; pending means local projection
  work remains. Counts refer to the local inventory and can grow during download.
- `migration inventory check`: time spent checking migration across a vault.
- `membership fetch cloud failure`, `incoming application failed`, and
  `persisted operation failure`: errors and durable blocked work.

Identifiers in new diagnostics are hashed; names, secrets, keys, and dependency
payloads are not logged. Correlate operation/item tokens across stages.

On October 21, a 15-minute Mac log capture contained 143,759 ready grant outcomes
returning `transportOwned`, versus 942 actual grant preparations. The scheduler
now suppresses repeat handoffs of ready operations within one drain; a later wake
can repair registration, and transport failures retain their retry rules. Grant
completion also no longer performs a whole-vault migration scan per item; pending
vault checks run at drain quiescence. These changes require a rebuilt app. They do
not establish an end-to-end iPhone throughput result without a new device run.

## Missing grants during head comparison

An iPhone trace subsequently showed repeated `MopContentHeadV3` application with
`local access grant missing`, about 13 ms per attempt and up to 199 attempts.
Generic dependency retries were being released by unrelated inbox completions.
Comparisons now persist a `GrantRequestWait` for the missing recipient/key
generation (plus the observed head and membership). `comparison waiting for grant`
marks this wait; grant arrival or a relevant state change allows re-verification.

The matching Mac trace showed 232 access requests in five minutes. Each repair
previously performed zone provision, single-record save, and readback serially
inside the scheduler. Repairs now emit `grant repair queued` and enter the durable
normal publication path, allowing CloudKit batching. Exact stored bytes, current
authority validation, and confirmed delivery remain required. The targeted repair
lookup avoids scanning all grants in the vault. This is a further fix beyond the
registration-churn change; device throughput must be measured with this build.

## iPhone CPU profile

The supplied 40.68-second sampled-weight profile attributed approximately 19.84 s
inclusive to migration grant transfer, 11.71 s to content-key path checks, and
8.32 s to hexadecimal formatting. These are overlapping CPU weights, not additive
wall-clock durations or an explanation of all cloud wait time. Successful path
checks were already memoized; migration repeatedly retried failing obsolete paths.
Migration now memoizes both outcomes within its immutable-history pass and reuses
recipient fingerprints. SHA-256 hexadecimal encoding now uses direct ASCII
conversion rather than 32 locale-aware formatting calls. Compatibility tests
compare against the previous encoding and a known digest. A new physical-device
profile is needed to quantify the improvement.

## Batched database reads

The scheduler now evaluates grant-request dependencies in groups of at most 64.
Within each group the runtime resolves membership once per vault, and the
repository reads observed heads, matching grant metadata, and requested archived
versions in one transaction (at most three fetches). Unknown dependency kinds use
the existing individual checks. Results live only for that scheduler pass; they
are scheduling hints, not authorization or proof of usable plaintext.

Migration reads versions and the two relevant recipients' grants for at most 16
items together, in one transaction with two fetches. It still processes current
heads first, verifies cryptographic bindings and epoch eligibility, and uses the
existing live-policy/CAS checks when committing grants. Cancellation and lock
checks remain at batch/item boundaries and at the protected commit.

Tests cover cross-account isolation, missing grants/versions, batch bounds,
dependency resumption after new data, and the existing migration restart,
concurrent-membership, removal, and rotation behavior. Physical-device profiling
is still needed to measure the resulting throughput.

## Health verification during sync

The later profile attributed about 46.7 seconds of sampled CPU time to
`healthChecks -> readableState -> verifyAccountPath`. Failed historical membership
checks were repeated for each health record. Session-local caching now retains
both success and failure for each membership digest (bounded to 256 entries).
The session's history and identity are immutable, and replacement sessions get a
new cache. Entries contain public membership results only. Health envelopes still
undergo binding/signature verification, and permit checks still enforce lock.

A display catalog waiting on grants can be settled without being complete.
Background health enrichment now waits for complete projection and completion of
initial download. Available items are published immediately with health evidence
marked loading; the final arrival resumes enrichment. This preserves unknown
health state instead of treating deferred checks as clean results.

### Targeted reconciliation and retained diagnostics

After a sync drain (including startup), and on an explicit prerequisite refresh,
reconcile active targeted fetches against trusted local history. Resolve a
membership fetch only if its exact digest is in that history; resolve an immutable
content-version fetch only after checking its canonical identity, scope, signed
envelope, metadata, and item kind. A local mutable head, a newer unrelated
membership, item availability, or operation age is never sufficient. Retained
coordination grant requests can be retired only when their valid signatures and
trusted membership path prove the requester was removed. Other work and
quarantines remain intact.

Resolution uses the exact operation revision and the account write permit. It
records a reason and timestamp without marking an upload delivered. Dependents
run their normal verification again. The journal retains cleanup records under
its existing retention policy; this is not a permanent audit archive.

The issue footer's Details button opens Sync Diagnostics; the normal status
footer's cloud icon also opens it after the issue clears. It shows pending work
and retained resolutions, operation/vault/item identities, exact requested
membership, hashed other dependency identifiers, attempt counts, dates, and
safe CloudKit error categories/codes. It never displays operation payloads or
raw server error descriptions. Existing failures have no retroactive underlying
error detail. New targeted-fetch failures record it separately, without changing
the worker's operation revision. Late failures cannot overwrite newer work.

Recheck and Retry performs the existing explicit prerequisite refresh and sync
request, resolving locally satisfied work and rearming retained targeted-fetch
transport attention when trusted history is available. Missing cloud records
still retain automatic backoff/retries. Service-imposed retry timing remains in
the scheduler. The view loads once and refreshes explicitly, shows 25 operations per page,
and closes on lock. Share reports are formatted off the main actor once per
snapshot, rather than on every SwiftUI redraw. The diagnostic view retains only
the service, so unrelated app-model activity does not invalidate its entire list. Unresolved records are preserved for targeted recovery rather than reset
or discarded on a timer.

### Untrusted-zone retry recovery and explicit discard

A canonical targeted fetch for a vault outside the adapter's independently trusted
address set now waits on `trustedContentZone`, with no retry timer. Discovery does
not satisfy this dependency. Verified admission/registration can resume the same
operation; account checks, canonical routing, signed membership verification, and
pinned-history application still run. Malformed bindings require attention rather
than repeated network retries. The old log's increasing attempt count was one
operation repeatedly failing a local routing gate, not repeated cloud failures.

The same log showed pending uploads increasing by 16 while successive rotation
batches cancelled engine sends. Rotation now awaits a send opportunity after
registering each batch and releasing its publication barrier. Send failures keep
publications durable and normal engine retry behavior intact. Look for `rotation
send opportunity` or `rotation send deferred` in logs.

Diagnostics also offers explicit date-scoped discard (initially October 16, 2026,
as requested), using the device's local calendar day. This includes unsent edits.
It pauses the local sync engine, archives encrypted operation/incoming/edit data,
removes matching pending mutations and incoming records, and records
`discardedByUser` without inventing delivery acknowledgments. Cached encrypted
item versions remain available locally for recovery. Newer and other-account
operations are untouched. Identical discarded incoming payloads are not requeued
on replay; changed payloads still follow normal ingestion and verification.
Discard is user-triggered, never an automatic age-based trust decision.

### Missing immutable grant sources on Mac (October 22)

The Mac journal and CloudKit diagnostics showed 14 exact-version fetches returning
`unknownItem`, with corresponding incoming grants waiting for those versions.
An older publication sequence could upload a grant before its immutable source;
a concurrent rotation could then supersede the source's pending head mutation.
The receiver correctly retained the grant without trusting it. Ordinary cloud
notifications also woke the scheduler as foreground events, resetting transport
backoff and amplifying the failure.

Grant publication now requires confirmed delivery of its exact immutable source.
If needed, the selector publishes the retained source as an immutable version,
without changing the current item head. At startup the sender re-arms retained,
completed grants whose source remains unconfirmed, provided current authority and
recipient checks still hold. Existing signature validation remains mandatory.
Explicitly discarded sources and grants are excluded; replay acknowledgments do
not renew grant receipt retention periods.

Look for `Sync trace: repaired missing grant source publications; grants=...` on
the device holding the source, and `content version cloud failure` on receivers.
Missing records wait on their exact content dependency with a five-minute recovery
retry. Verified arrival can resume work sooner. Ordinary cloud refreshes use a
store-change wake rather than resetting foreground backoff. Install the repair on
both devices: a receiver cannot reconstruct an absent encrypted source. Recovery
retains unresolved work if no device has the required source.

### Password-health saves after device replacement

`MopCore.MopError` NSError code 36 in this build is `vaultUntrusted` (not a
CloudKit error or the CLI exit code). A historical, validly signed local health
cache may refer to membership predating the current device. Reading already
omitted that unusable evidence, but saving reopened it for merging and could fail
on the historical membership path after the previous device was removed.

Saving now verifies current content access first and discards only the exact
obsolete local health-cache version when historical trust or recipient access
prevents reuse. Fresh checks are sealed under current membership. Historical
verification is not relaxed, old evidence is not merged, item data is unchanged,
and authentication failures still propagate without deleting the cache. Parent
and cache-version comparisons continue to reject concurrent changes. Logs now
include the safe MopError description; `Health evidence saved` confirms a save.

### Retiring unused missing-source grants

The 14 Mac source fetches were all for incoming grants whose key generations
were absent locally and differed from the current item generations. Each current
item had a replacement grant for the same recipient; there were no pending edits
or conflict branches. Sender repair cannot republish bytes absent from the Mac,
and retaining every incoming grant indefinitely left these requests retrying.

Targeted reconciliation now archives the unused grant and fetch together after
an `unknownItem` diagnostic, verified current content, and verified replacement
grants. The commit rechecks current head, policy, source absence, replacement
grants, inbox records and competing dependencies. Pending edits, conflict work,
other consumers, invalid signatures and network failures prevent this cleanup.
It does not delete item versions, acknowledge delivery or accept the old grant.
Look for `unused grant source retired`; diagnostics show `unneededGrantSource`.
Identical useless replays stay suppressed, but a later source arrival can reopen
normal grant verification and a new consumer can rearm the exact source fetch.
Encrypted recovery records remain archived.

### Terminal enrollment failures and quarantine accounting

The Mac's 35 `enrollment/invalidAuthority` entries were signed grant requests for
archived key generations. All 35 had local ancestor paths to current content;
existing terminal recovery only handled removed requesters and never reconsidered
still-authorized requests against later trusted state. Recovery now strictly
revalidates request signature, account/scope, membership path and recipient, then
uses the ordinary grant prerequisites. Verified successor generations retire with
`obsoleteGrantGeneration`; unknown generations retain their dependency waits;
current requests resume normal delivery repair. An observation marker limits
retry to once per unchanged trusted membership/head state, including restart.
No recovery resolution creates a delivery receipt or weakens grant verification.

All 197 reported quarantine records were already marked retired. The old summary
counted retained evidence as active quarantine. Startup now logs `quarantined`
(active only) separately from `archivedQuarantine`; encrypted evidence remains
retained. Unverified active quarantine records remain active. Look for `obsolete
enrollment grant generation retired` or `verified enrollment grant request
resumed` to distinguish cleanup from resumed work.
