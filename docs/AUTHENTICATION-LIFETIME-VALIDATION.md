# Background authentication and inactivity

The app's inactivity deadline and Secure Enclave authorization are independent.
A native noninteractive operation can require user presence before the app's
configured deadline. Background catalog refresh now preserves the live session
and verified displayed data for that specific failure, reports that updates need
authentication, and leaves the inactivity deadline untouched. It neither retries
with interactive authentication nor treats the failed operation as successful.
Other authentication failures, account changes, removal, and explicit/system
locking retain their existing behavior. Foreground protected operations still
require authorization. No keys, identities, grants, or access controls change.

This fixes the premature application lock; it does not extend Apple's hardware
authorization lifetime or guarantee unattended cryptographic work for 60 minutes.
To resume work requiring renewed presence, explicitly lock and unlock the app.

## Signed Mac validation

1. Install a signed build containing this change. Set inactivity to 60 minutes.
   Unlock the vault; record the time and current migration confirmation count.
2. Keep the Mac awake and its screen unlocked. Do not run Grant Maintenance Apply
   or any cleanup operation. Leave the iPad closed during migration.
3. After 11 minutes, trigger ordinary refresh or return to the app. If the native
   authorization expires, confirm the existing catalog remains visible and the
   authentication notice appears, rather than the lock screen. Check that failed
   grant work stays pending and publication receipts remain intact.
4. Explicitly lock/unlock and confirm the pending work resumes, with the same
   device identity and unchanged content keys.
5. In a separate run, leave the app idle for 60 minutes, with the Mac awake and
   screen unlocked. Confirm inactivity locking still occurs. Separately verify
   manual lock and macOS screen lock immediately conceal content.

Automated tests simulate the native error and clock boundaries. They do not
prove Secure Enclave behavior or live iCloud progress on a signed device.

## Returning iPad after replacing a deleted vault

Use a disposable vault for deletion testing; do not delete production grants to
validate this flow. Install the updated build on both devices. Keep the Mac
unlocked with the replacement vault available.

1. On an iPad with the old vault selected, let its signed deletion arrive. Tap
   Unlock. Discovery must discard the old selection and show the replacement's
   connection status without requiring a second unlock.
2. Repeat with no enrolled vaults and an empty cached discovery list. Unlock must
   refresh discovery before choosing the local-only unlock path.
3. Finish Face ID while observing scene inactive/active notifications. A successful
   response just before activation must remain successful. Backgrounding or
   explicitly locking during an unfinished prompt must still cancel it.
4. Allow the Mac to approve/share access. The iPad must advance from waiting for
   access through metadata download to the verified catalog automatically. Repeat
   with admission already complete when Unlock is tapped.
5. Lock manually and send another cloud update: it must not reopen the catalog.
   Verify the configured inactivity timeout is unchanged.

Automated state-machine regressions cover these transitions, but cannot establish
real Face ID callback ordering or successful live CloudKit enrollment.
