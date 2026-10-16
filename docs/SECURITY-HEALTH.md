# Device-local password health and secret history

Password-health results remain on each device and are recomputed independently.
Credential-account registration and redundancy management are unimplemented roadmap
requirements; their models and screens have been removed.

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

## Local cache and scheduling

Strength, breach and reuse have independently dated results. HIBP results expire
after 24 hours; strength depends on the secret, account context and evaluator;
reuse depends on the accessible active password set. Changing a password invalidates
its old evidence. Failed requests do not advance a successful breach timestamp.

`LocalPasswordHealthEnvelope` authenticates encrypted per-item cache records.
Parent-version checks reject stale writers. The encrypted local security index
reuses unchanged results after restart; damaged derived caches are treated as unknown
and recomputed. Writes create no cloud publication and do not alter item edit dates.
The existing encryption domains remain unchanged. Plaintext results, index keys and
scan authorization are cleared on lock, and cancellation/session checks discard
late work. Neither password hashes nor scan HMAC keys are persisted.

Automatic work waits after unlock and for idle foreground time, yielding between
fields. Explicit checks and changed-password checks can bypass the startup delay.
Results appear incrementally; completed cache batches survive cancellation, while
reuse coverage remains incomplete until the scan finishes. This is unlocked app
work, not a guarantee of execution while the app is closed or locked.

Portable archive v2 excludes derived health results. Each restored device computes
its own findings. There is no companion synchronization, rewrapping or health
conflict-resolution workflow.

## History semantics and schema

Eligible password and concealed-field edits retain previous values in the encrypted item envelope. Local commit establishes the change and its history; delayed or failed cloud delivery does not undo that commit. Item drafts alone do not create history.

History is associated with stable field identities and excluded from ordinary secret references, search and AutoFill. Explicit history reads require authentication. Restore is an ordinary edit that retains its predecessor. Portable archives preserve retained history and trash/restore preserves the item contents.

Clearing history affects the current stored item; it cannot erase values from exported archives, remote copies or a recipient's memory. Account recovery includes retained history; see [recovery](OFFLINE-RECOVERY.md). Physical acceptance remains pending. Physical conflict/history preservation and deletion semantics remain release acceptance work.

## Acceptance

Current tests must cover restart caching, no cloud publication, stale parents,
damaged caches, cancellation, and clearing authorized plaintext on lock. Historical
test passes do not validate this cleanup. Physical-device authorization and iCloud
acceptance are reported separately from software checks.
