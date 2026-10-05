# Security health, device-local credential backups, and basic secret history

Implementation scope: SALE-2, SALE-3, and a first increment of SALE-11. Physical
Secure Enclave, cross-device/CloudKit, accessibility, and real-service acceptance
remain release gates. Automated software-key tests do not establish those properties.

## Current integration

Password-check caching and per-item history read/restore/clear use the item service. Credential-account registration and redundancy management remain unavailable. All participating clients should use compatible item schemas. Hardware and real-service acceptance remain separate from software tests.

## Password checks

Security groups exposed, reused, and weak passwords, and links findings to the
normal item editor, generator, website link, and per-field history. Editing a saved
password does not change the password accepted by a service.

The scanner covers password-typed fields and explicit AutoFill password mappings
in accessible catalogs. Archived items, Recently Deleted items, historical values,
API tokens, OTP seeds, and unrelated concealed fields are excluded. Reuse compares
exact bytes across distinct items using a fresh, memory-only HMAC key per scan.
Weak and very weak ratings use the existing estimator with account context.

HIBP is enabled by default and can be disabled in Security or Security settings.
Only a five-character SHA-1 prefix is sent to the HTTPS Pwned Passwords range API,
with response padding. Full hashes, passwords, account names, and website addresses
are not transmitted. HIBP also sees the network address. No checks run while typing.
Redirects are refused; cookies and persistent HTTP caches are disabled. Range
responses are validated; zero-count padding is ignored. Checks use one outstanding
request at a time, sharing successful ranges within the unlocked session for at
most 24 hours. Check Now clears that cache. Lock clears the session's results and
cache and cancels outstanding scan work; revision/session guards discard stale work.

Local findings are displayed before network checks complete. Coverage, last-check
time, disabled/incomplete checks, and inaccessible vaults remain visible. A clean
result describes only checked items and is not proof that an account was never
breached. A matching password is described as appearing in known breach data.

## Account and credential evidence

Credential-account registration and redundancy management are not connected to the current service. The planned workflow distinguishes generated keys from credentials actually registered and tested at an external service. An alternate must be a distinct confirmed credential on another device; two keys on one device do not establish device redundancy. No software record can back up a device-local hardware private key.

## History semantics and schema

Eligible password and concealed-field edits retain previous values in the encrypted item envelope. Local commit establishes the change and its history; delayed or failed cloud delivery does not undo that commit. Item drafts alone do not create history.

History is associated with stable field identities and excluded from ordinary secret references, search and AutoFill. Explicit history reads require authentication. Restore is an ordinary edit that retains its predecessor. Portable archives preserve retained history and trash/restore preserves the item contents.

Clearing history affects the current stored item; it cannot erase values from exported archives, remote copies or a recipient's memory. Live account recovery and permanent vault deletion are unavailable. Physical conflict/history preservation and deletion semantics remain release acceptance work.

## Validation evidence — October 2, 2026

- Full `swift test --disable-sandbox` passed with the repository's cache overrides
  and required local-system access: 467 Swift Testing tests across the package
  targets. An additional focused editing-state regression and the existing delayed
  password-read scenarios also passed after the final scan-pause adjustment.
- macOS app and AutoFill builds passed with `CODE_SIGNING_ALLOWED=NO` and the
  existing package cache. The macOS UI runner exited with signal kill before
  bootstrapping; this is not a macOS UI acceptance pass.
- The new UI test passed separately on iPhone 17e and iPad Pro 11-inch simulators
  (iOS 27). It exercises Security findings, account navigation,
  opening history, concealed initial values, reveal, and conceal. Separate simulator
  runs are used: a combined-destination retry stalled with an incomplete result
  bundle and was terminated after confirming no active test runner remained.
- Regression coverage includes retention, stable field-path swaps, token/password
  type conversion, clear/delete, unchanged writes, viewer restrictions, rename,
  trash/restore, recovery/rotation, encrypted backup, service synchronization,
  stale restore rejection, exclusive-backup failure, HIBP parsing/padding/caching,
  exact-byte reuse, unreadable coverage, archive/deletion exclusions and mapped fields, registration
  confirmation, same-device/same-key exclusions, and observed local removal.

Still required before marking SALE-2/SALE-3 complete: physical Secure Enclave and
real-account registration tests, cross-device CloudKit acceptance, signed macOS UI
execution, and the full SALE-8 accessibility/appearance/device-size review. These
checks do not establish production CloudKit deployment, cross-account permissions,
or permanent deletion of previously retained encrypted copies.

### Independent check lifecycles (2026-10-04)

Only HIBP results expire with time: successful checks are refreshed after 24 hours
while unlocked, with retry backoff on failure. Check Now bypasses that expiry and
the automatic startup delay. It does not discard valid strength or reuse results.
Strength results remain valid for the same secret record, account context, and
estimator version. Reuse results remain valid for the same set of accessible active
secret records; adding, replacing, archiving, deleting, or losing access to a
credential can change another item's reuse finding. Account-label changes do not
invalidate reuse or an unchanged password's HIBP result.

Strength, breach, and reuse have independently dated results in per-item encrypted
health companions. A successful HIBP result is bound to the immutable password
record and remains valid across devices for 24 hours. Editing another item, updating
reuse groups, or changing an account label does not reset that clock. A replacement
password is immediately eligible; a failed request does not advance the successful
check timestamp. Check Now remains an explicit refresh override. Simultaneously
checking devices or devices that have not received cloud updates can still duplicate
requests; synchronization is not a distributed request lock.

Health companions use signed, domain-separated encryption and the existing CloudKit
item transport, with authenticated parent-item routing. They sync independently of
login content and vault settings, and do not change item edit versions or dates.
Each device maintains an encrypted local security index keyed by companion versions,
using its existing device-wrapped catalog-cache key. Decrypted index state is cleared
on lock; reopening unchanged results needs one local index-key unwrap. No password hashes or session fingerprints are persisted.
A changed companion refreshes the security projection even when item versions are
unchanged. Competing writes retain the latest successful timestamp independently
for each check. Partial or mixed-batch reuse evidence is not accepted as complete;
strength and breach evidence can still be cached independently.

Companions are excluded from item counts, secret references, search, AutoFill, and
portable backups (restored vaults recompute derived results). Device admission and
membership catch-up reencrypt them for admitted recipients. No legacy-client
compatibility is promised for the new record kind. Real CloudKit propagation and
simultaneous-device behavior still require device acceptance testing.

Automatic work waits 30 seconds after unlock, then waits for five seconds without
user activity and for foreground work, editing, and backgrounding to end. It yields
again between fields. Restoring already-valid cached results does not need this delay
and does not show a checking thermometer. Delayed work is canceled on lock or session
change. These checks run while the app is unlocked; this is not an OS background-job
guarantee when the app is closed or locked.

Validation for the October 4 lifecycle/storage update: the full Swift suite passed
with the documented sandbox accommodations. Focused regressions cover another
item changing without restarting a password's 24-hour breach clock, unchanged
item ciphertext and metadata, stale cache writers, encrypted local-index reuse,
wire binding, admission rewrapping, and startup/idle deferral. macOS app/AutoFill
and iOS Simulator app/extension builds passed with signing disabled. This does not
replace the physical-device and real CloudKit acceptance checks listed above.

Scanning publishes incremental reports: the first completed field is shown and
queued immediately, then completed work is flushed after ten additional fields or
one second between completed-field boundaries, with a final flush at completion.
Each batch updates the Security UI and durably queues changed encrypted observations
for iCloud; it does not wait for cloud delivery. Partial writes preserve evidence
for unvisited fields. Reuse comparison remains incomplete until the scan completes.
Session/revision guards prevent stale publication, and committed batches survive
cancellation or locking. Own-cache updates do not restart the running scan.

After a successful item save, changed-password checks bypass the automatic
startup/idle grace period without forcing HIBP refreshes for unchanged passwords.
Fields needing strength evaluation run first. Their local strength results reach
the detail warning, Weak Passwords list, and All Findings list before waiting for
HIBP; a strong replacement clears the weak finding once evaluated. Other valid
findings can keep the item in All Findings. The remaining network/reuse work keeps
its incomplete state until finished.

Strength observations include the full five-level rating, not just the weak-finding
boolean. Receiving devices project that rating onto the matching current field
only when its account context and evaluator match. The detail meter uses this synced
rating directly; older observations without a rating fall back to local password
estimation without requiring an online vault open. Software tests cover encrypted
admission/receipt and the receiving catalog projection; physical iCloud propagation
still needs device verification.
