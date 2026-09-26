# Native app

The SwiftUI Mac/iPhone/iPad app, CLI and AutoFill use the same v6 service and
device-local identity. Old-format vaults are not displayed or converted.

## Guided setup

Successful iCloud discovery with no v6 vaults opens **Create a vault**. Enter a
name and authenticate; Mop generates the device’s hardware keys and opens the
vault immediately. Recovery is optional and does not block creation. A notice
explains the risk of losing the only authorized device.

When iCloud contains v6 vaults that this device cannot access, **Connect this
device** opens instead. Selecting an unenrolled vault also opens that flow.
Discovery does not authenticate cloud data or create a local trust pin. Failed
CloudKit discovery reports an error rather than claiming the account is empty.

On your own new device, Mop generates keys and submits a signed request through
iCloud. An unlocked owner device processes it automatically without a dialog.
The new device shows progress and asks you to unlock Mop elsewhere if waiting.
It opens the vault when the signed grant arrives. Existing owner devices show an
in-app notice once per added device, based on signed membership, including after
the enrollment mailbox expires.

Polling runs every 15 seconds on the unlocked owner app (macOS can also process
while its window is inactive; iOS requires the app to be active), or every 5 seconds
on the connection screen. Locked or suspended apps cannot grant access; automatic
processing does not authenticate or extend the inactivity timeout. Delivery while
the OS suspends an app is not guaranteed. Retry and restart remain available.

**Share with another person** is separate: choose editor/viewer access and use
the private iCloud share URL during acceptance. Cloud enrollment is private-database/same-account only; other-account sharing
uses the separate explicit invitation and permission flow.
Explicit approval remains necessary for cross-account sharing.

**Set up or replace hardware recovery** can be used after secrets are saved.
Generate the recovery request on a separate device and import it on an owner
device. This grants recovery access to existing contents. Adding recovery does
not change passwords; replacing recovery rotates current encryption keys.
Advanced access management retains member/device removal, role changes,
checkpoint import and cloud permission reconciliation.

## Items and sessions

The existing item editor supports typed fields, renaming, password-strength metadata, concealed values, TOTP, trash/restore and encrypted backup export. Catalog browsing opens its own key; revealing a password opens that record's key. Values passed to an edit are plaintext inside Mop. The catalog stores concealed fields without values.

The app retains its authenticated LocalAuthentication context until lock/expiry. Device key handles and individual encryption keys are released after operations. Switching apps does not itself revoke the session; explicit lock and inactivity expiry invalidate it and reject late results. Concurrent edits fail instead of silently overwriting another revision. Refresh and review before making a new edit.

Offline browsing is explicit and read-only. It cannot establish remote freshness or revocation. The CLI and GUI share device-local app-group checkpoints; never synchronize their local state directory.

## Recovery

**Recover an existing vault** is also available from creation on a device with no local vaults. On the enrolled recovery device, import the encrypted backup, verify its checkpoint, and paste independently verified replacement owner/recovery requests. Return the resulting encrypted checkpoint to the replacement owner and use **Import trusted checkpoint**. Lost-account recovery creates a new UUID/root under the current account and retains the source; the replacement owner request must belong to the recovery device's ordinary identity under that new account.

If all authorized and recovery device keys are gone, neither a backup nor account restoration is sufficient. Keep the recovery device separate. [Validation](VAULT-NEXT-VALIDATION.md) lists remaining physical acceptance, including second-account sharing and actual iOS/AutoFill hardware.

## Enrollment status and restarting

The connection screen shows the current stage, request ID/expiry, check start time
and last successful iCloud contact. Authentication and network failures are shown
inline instead of silently stopping the polling loop. **Check iCloud now** retries
and authenticates if needed. Background/inactive sessions do not poll.

If the two devices disagree, choose **Restart connection** on the new device.
This creates a fresh signed request, clears the old comparison/confirmation, and
retires prior pending requests in iCloud. Connection proceeds automatically.
No vault contents or device keys are deleted. A durable list of replaced request
IDs lets a later retry finish retirement after an interrupted cloud update.
**Cancel request** pauses enrollment and retires the current pending request;
ordinary polling does not silently recreate it. Cancellation is retried if iCloud
did not confirm it. Neither action revokes access that was already granted.

A missing server invitation clears the locally displayed comparison code. A
conflict clears stale UI state and triggers another check. A network/authentication
failure pauses polling with an explicit retry message; it does not present cached
state as proof that the server accepted a request. These controls require updated
builds on the participating devices.

## Remove and reconnect a device

On Mac, iPhone, or iPad, open **Settings → devices**. The list
shows device names where available, UUIDs, and which device you are using. Select
**Remove…** and confirm. Removal covers the personal vaults enrolled on the
managing device; it does not claim to revoke access to vaults that device has
never enrolled in. Cross-account membership remains separate. You may remove the
current device, but every affected vault must retain another owner device.

Removal publishes signed revisions with fresh encryption material and without
the removed device's key envelopes. The device's retired UUID cannot be reused
for enrollment. Multi-vault publication is not atomic; retry after an error to
finish any remaining vaults. Completed removals are safe to retry.

When the removed device next refreshes online, it verifies the revocation, deletes
its ordinary device identity's local Keychain record, and clears local catalog/
checkpoint caches, pending enrollment records, and AutoFill suggestions. A small
account-scoped removal marker and lock/binding metadata remain so relaunching
does not enroll again. Cleanup failures are retried before reconnecting.
Explicitly exported backups and separate hardware recovery identities are retained.

The removed device shows **This device was removed** and a **Reconnect** button.
Only that action opts it back in. Connection then uses fresh hardware keys and
the normal automatic same-account flow. An offline device cannot learn about
revocation until it reconnects; previously copied plaintext cannot be revoked.

## Settings layout

Open **Mop → Settings…** (Command-comma) on Mac, or the Settings gear on iPhone
and iPad. The **devices** section contains the device list, removal, and Add my
device. The **vault** section has a vault picker plus rename, checkpoint, backup,
membership, sharing, recovery, advanced access management, and deletion controls.
The vault row's ellipsis opens this same Settings interface for that vault.
There is no separate Vault Settings dialog. Action sheets and backup destination
selection are presented from Settings. The iOS Done button remains visible while
scrolling through the sections.
