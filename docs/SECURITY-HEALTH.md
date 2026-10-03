# Security health, device-local credential backups, and basic secret history

Implementation scope: SALE-2, SALE-3, and a first increment of SALE-11. Physical
Secure Enclave, cross-device/CloudKit, accessibility, and real-service acceptance
remain release gates. Automated software-key tests do not establish those properties.

## Compatibility and upgrade

New vaults enable `secret-history-1` and `credential-redundancy-1`. Existing v7
vaults can still be read and checked without modification. Their owner can choose
Upgrade Vault from Security, acknowledge the old-client incompatibility, and choose
a backup folder. The service exports an encrypted backup without replacing an
existing file, reopens and verifies it against the current checkpoint, and only
then publishes an upgrade revision. A stale revision, failed backup, or publication
conflict does not silently replace the current cloud head. Keep the recovery copy
separately. Update the app, companion CLI, and extensions on every device first.

This is a **breaking v7 schema extension**, not a v8 cryptographic replacement.
Old clients reject the required features. Flags cannot be removed by a later
revision. There is no in-place downgrade or attempt to recover passwords overwritten
before upgrading. Old backups remain readable in updated clients; restoring a
backup must not bypass checkpoint trust or replace a newer live head.

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

Registration records live inside the encrypted catalog of an explicitly selected
cloud vault, with its normal membership permissions and visible sharing audience.
They are not counted as credential items. Records identify service/account, optional
linked item, protocol, public credential identifier, device, confirmation state/date,
and confirming actor. Local private keys never enter these records. Passkey metadata
prefills the relying party and account when linking; similar names are not merged.

Each registration is generated, explicitly confirmed by the user after registering
and testing it at the service, or removed/revoked. Generating a key, returning a
WebAuthn registration response, or producing a local signature is not service
acceptance. An alternate requires distinct confirmed credentials on different
devices; two keys on one device do not qualify. Manually entered external devices
and keys are labeled. A confirmation is dated user evidence, not live verification.

Removing a vault device invalidates its registration evidence. A successfully loaded
local inventory can invalidate records for keys no longer on the current device;
network/listing failures are not evidence of deletion. Unlinked identities remain
unknown. Recovery/reissuance procedures are stored separately and do not count as
registered alternates. Read-only or offline views cannot update evidence.

## History semantics and schema

Eligible fields are `.password` and `.concealed`, covering password and API-token
values and raw CLI secrets. Every engine write compares actual bytes before retaining
a predecessor. Item drafts and failed cloud publication do not commit history.
The newest twenty previous values per field are kept without age expiry. Existing
vault capacity limits still apply; exceeding them fails the write rather than
silently pruning below the retention rule.

The encrypted `CatalogPayload.security` contains `histories` and `accounts`.
Each eligible field has a stable `historyID` UUID. Its history retains that UUID,
item UUID, current field path, and entries containing an
encrypted-record ID and replacement date. Item and field renaming changes live reference
paths but not history identities. Field-path swaps preserve each field’s history. History records use the existing item key and
field authenticated context. They are excluded from current reference enumeration,
AutoFill, normal search, and normal secret reads. Validation requires disjoint
current/history record ownership and matching item keys. Rotation remaps both
current and historical record IDs; membership and offline recovery cover both.
No new CloudKit record type is introduced.

Readers can reveal/copy previous values; editors and owners can restore or clear.
Restore is another ordinary write and preserves its predecessor. Reveal is concealed
on inactivity/app switching and after thirty seconds; copying uses the existing
secret clipboard policy. Field deletion and item purge remove live history; trash
and restore retain it. Existing encrypted backup/restore includes history.

**Clear History is not permanent erasure from old revisions, backups, or copies.**
Restoring a value does not change the service or reactivate a revoked token. Full
item snapshots, imported historical values, permanent historical-copy deletion,
and the broader SALE-11/SALE-9 acceptance remain separate work.

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

### Incremental checking and freshness

Successful password-health results and their timestamps are cached inside each
upgraded vault's encrypted security metadata and synchronize through normal iCloud
revisions. A complete cache for the same accessible active fields can be reused for
24 hours after checking, including after lock, app restart, or on another device,
without reading password values or making HIBP requests. Check Now bypasses freshness.
The UI retains the original check date and identifies saved iCloud results.

Each result is bound to its immutable secret record, account context, evaluator
version, and a scan scope derived from active record identities. Scope contains no
password hashes. Reuse groups use random identifiers; a shared batch identifier
prevents partial cross-vault synchronization from being mistaken for a complete
reuse result. Changed values, account context, accessible fields, archive/deletion,
or expired results invalidate the applicable cache. When reuse needs rebuilding,
only session-keyed fingerprints are used; those fingerprints are never persisted.

Cache publication is revision-bound and uses owner/editor permissions. Readers can
consume saved results. It is skipped during editing, foreground work, or offline;
failed publication leaves local results available and is reported separately.
Unchanged catalog assignments, item selection, and cache-only revision publication
do not restart checks. Previously successful breach evidence keeps its original
check date when a refresh fails; retries back off from one minute to one hour.

The optional `passwordChecks` metadata is disposable and introduces no new required
feature or vault upgrade. Older clients may discard it, causing a later recheck,
without losing vault contents. Existing security-feature upgrade requirements still
apply to vaults that have not been upgraded. Encryption, sharing permissions, normal
size limits, and encrypted backup retention apply to cached results too. Lock and
account changes clear decrypted session caches and cancel scheduled work; encrypted
results remain in the vault for reuse after authentication. Key rotation may discard
derived results because record identities change.

Cloud-cache validation: all 476 Swift tests passed, including fresh-session reuse
with zero password reads/HIBP requests, forced and expired checks, changed-record
invalidation, mixed synchronization batches, encrypted backup round trips, viewer
write denial, stale publication rejection, and two-client synchronization using the
in-memory cloud transport. macOS app/AutoFill and iOS Simulator builds passed.
These automated tests do not substitute for physical-device iCloud synchronization
acceptance.
