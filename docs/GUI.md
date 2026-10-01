# Native app

The SwiftUI Mac/iPhone/iPad app, CLI and AutoFill use the same v7 service and
device-local identity. Old-format vaults are not displayed or converted.

## Guided setup

Successful iCloud discovery with no v7 vaults opens **Create a vault**. Enter a
name (the displayed Personal default creates `personal`) and authenticate; 2ndPass generates the device’s hardware keys and opens the
vault immediately. Recovery is optional and does not block creation. A notice
explains the risk of losing the only authorized device.

When iCloud contains v7 vaults that this device cannot access, **Connect this
device** opens instead. Selecting an unenrolled vault also opens that flow.
Discovery does not authenticate cloud data or create a local trust pin. Failed
CloudKit discovery reports an error rather than claiming the account is empty.

On your own new device, select the desired vaults and choose **Connect**. 2ndPass generates keys and submits signed requests through
iCloud. An unlocked owner device processes it automatically without a dialog.
The new device shows progress and asks you to unlock 2ndPass elsewhere if waiting.
Each vault reports its own result when the signed grant arrives. Completion does not replace your current selection or discard an item draft. Existing owner devices show an
in-app notice once per added device, based on signed membership, including after
the enrollment mailbox expires.

A model-owned coordinator checks every 15 seconds while unlocked. Closing the
connection screen keeps submitted requests active. macOS can also process while
its window is inactive; iOS/iPadOS resume checks when the app is active. Locked or suspended apps cannot grant access; automatic
processing does not authenticate or extend the inactivity timeout. Delivery while
the OS suspends an app is not guaranteed. Retry and restart remain available.

**Share with another person** is separate: choose editor/viewer access and use
the private iCloud share URL during acceptance. Cloud enrollment is private-database/same-account only; other-account sharing
uses the separate explicit invitation and permission flow.
These cross-account controls are preliminary: vault sharing is not yet a
completed, supported feature. The [mailbox design detail](SECURITY.md#shared-zone-enrollment-exposure)
must be addressed when implementing sharing; it is not a current vulnerability. Same-account
bootstrap deliberately relies on Apple's account/device security and provisioned,
entitlement-protected private CloudKit access; credentials alone do not grant
container writes. See [the threat model](SECURITY.md#automatic-same-account-enrollment)
for automatic admission risks when that access path is compromised.

## Items and sessions

The existing item editor supports typed fields, renaming, password-strength metadata, concealed values, TOTP, trash/restore and encrypted backup export. Catalog browsing opens its own key; revealing a password opens that item's key. Values passed to an edit are plaintext inside 2ndPass. The catalog stores concealed fields without values.

2ndPass attempts authentication once at launch while active. After cancelling, locking,
inactivity expiry, or waking from system lock, choose **Unlock 2ndPass** to authenticate.
Pointer movement, typing, returning to the app, and Refresh do not unlock a locked
session. Refresh discovers vaults while locked and updates catalogs while unlocked.
Settings can be opened without authenticating; protected device details offer Unlock.

The app retains its authenticated LocalAuthentication context until lock/expiry.
Device key handles and individual encryption keys are released after operations.
Password editors start concealed and have an explicit reveal button. Switching apps
conceals revealed values and password inputs without discarding the in-memory draft;
returning does not reveal them again. The same rule applies to brief mobile backgrounding.

Leaving a modified item, changing its vault context, refreshing, or normally closing
or quitting the Mac app offers **Save Changes**, **Discard Changes**, or **Cancel**.
Saving completes the requested action only after the save succeeds. Invalid or offline
drafts can be retained or discarded. Recoverable failures preserve edits. Concurrent
changes retain the draft and block further saves until you explicitly discard it and
refresh; 2ndPass never silently overwrites another revision.

Explicit lock, inactivity expiry, system lock/sleep, account loss, device revocation,
and termination clear drafts and reject late results immediately. Security locking
never waits for an unsaved-changes dialog. Drafts are not persisted across lock or
restart; save important changes before leaving the session.

Unlock opens the selected vault from its verified local checkpoint after authentication and account validation, when a checkpoint is available. The UI is read-only while that cached catalog is displayed. An immediate background sync checks for changes, deletion, and revocation; successful refresh enables editing. Without a local checkpoint, unlock fetches the vault online first. Network failures preserve read-only access to the verified cache; trust, account, and access failures clear the session.

Cached browsing cannot establish remote freshness or revocation. Local checkpoint verification and catalog decryption still occur during unlock, so their cost grows with vault size. The CLI and GUI share device-local app-group checkpoints; never synchronize their local state directory.

## Recovery

Open **Settings → Recovery → Setup and Verification** to generate and verify a copy. See
[offline recovery after device loss](#offline-recovery-after-device-loss) below.

## Enrollment status and restarting

The connection screen reports each selected vault separately: contacting iCloud,
waiting for another unlocked device, paused, offline, connected, cancelled, or
failed. Only active work animates. Last successful contact appears as a relative
time. Failed checks show **Retry**; paused authentication shows **Unlock and Retry**.
Automatic checks never start a new authentication prompt.

Closing the screen continues submitted requests while unlocked. **Cancel Request**,
under Troubleshooting for each vault, retires that request; the UI reports cancellation
only after iCloud confirms it. An uncertain response remains an error. **Restart
Connection** replaces the request without deleting vault contents or device keys.
Neither action revokes access already granted. Conflicts retry on a later check;
other failures need an explicit Retry.

Background enrollment does not disable browsing or editing. Native service writes
remain serialized. Device notices identify the connected device and vault and offer
**Review Devices**. Settings shows names first, with IDs and affected vaults in Details.
Removal explains last-owner limits and reports confirmed progress if a later vault
fails. Removing this device remains explicit and requires Reconnect to join again.

## Remove and reconnect a device

On Mac, iPhone, or iPad, open **Settings → Devices**. The list
shows device names where available, UUIDs, and which device you are using. Select
**Remove…** and confirm. Removal covers the personal vaults enrolled on the
managing device; it does not claim to revoke access to vaults that device has
never enrolled in. Cross-account membership remains separate. You may remove the
current device, but every affected vault must retain another owner device.

Removal publishes signed revisions with fresh encryption material and without
the removed device's key envelopes. The device's retired UUID cannot be reused
for enrollment. Multi-vault publication is not atomic; retry after an error to
finish any remaining vaults. Completed removals are safe to retry.

The removed device shows **This device was removed** and a **Reconnect** button.
Only that action opts it back in. Connection then uses fresh hardware keys and
the normal automatic same-account flow. An offline device cannot learn about
revocation until it reconnects; previously copied plaintext cannot be revoked.

## Settings and Vault Details

Open **2ndPass → Settings…** (Command-comma) on Mac, or the Settings gear on iPhone
and iPad. Security, AutoFill, Devices, and Advanced are separate categories. 2ndPass
remembers the last category. Security offers inactivity presets and a custom
minute value. Opening Settings neither selects a vault nor authenticates.
Devices loads protected information only while unlocked.

Action sheets capture their vault when opened. Their action buttons stay below
scrolling content; errors appear with the form. Cancel or Escape asks before
discarding modified inputs. Interactive dismissal is disabled while inputs are
unsaved. Sharing steps retain their input when switching between steps. File
picker cancellation is silent, and backup names include the vault, date, and a
unique suffix. Mac users can reveal a completed backup in Finder.

## Search and item layout

Command-F focuses native search. Search filters the current scope, including
Recently Deleted, and retains its query when changing scopes. Only item names,
vault names, and nonsecret field names/values match. Filtering does not replace
the open item or discard a draft. Return opens the highlighted result; arrow keys
move the search highlight. Clear Search restores the full list.

The sidebar uses native collapsible sections. Item fields use separators and
visible Copy controls. Nonsecret text and notes support text selection; clicking
a value does not copy it. Website fields offer Open Website. Passwords retain
explicit reveal/conceal and protected clipboard behavior. Mobile controls retain
44-point targets and adapt for accessibility text sizes. The app respects the
user’s split-view column visibility rather than resetting it as windows resize.

### Password import progress

The import preview scrolls independently of its footer. **Refresh Preview**,
**Cancel**, and **Import N Items** remain visible; changing the selection replaces
Import with **Review Selection** until the updated preview is ready.

Starting an import dismisses the dialog and transfers the operation to the app
model. A persistent banner at the bottom of the main window shows a horizontal
progress bar: actual completed-item counts during encryption and indeterminate
activity during checking and cloud publication. Once the service confirms the
result, the banner shows the import summary until dismissed. An uncertain cloud
commit is shown as pending confirmation, with guidance to refresh before retrying.
Locking clears the retained report and prevents a late result from repopulating it.

## Offline recovery after device loss

Set up recovery before losing access to your devices:

1. Unlock 2ndPass and open **Settings → Recovery → Set Up or Verify Recovery…**.
2. Select **Generate a New Recovery Copy**.
3. Choose **Save Recovery File…** or **Print Recovery Copy…**, or write down the
   displayed code. Store your copy offline, separate from your devices and iCloud.
4. Use **Import Recovery File…** to load the saved file, or re-enter your
   written copy in **Recovery code**.
5. Select **Verify Copy and Activate**, then **Check Coverage**. If any vault is
   unfinished, select **Resume Incomplete Changes** until every vault is complete.

Recovery applies to all your owned iCloud vaults, regardless of the selected vault.

On a replacement device, sign into the same Apple Account. Open
**Settings → Recovery → Recover Vault Access…** (or choose recovery during
onboarding), then import the copy or enter its code. Read-only recovery can open healthy data while unavailable
attachments postpone completion. Complete each vault to rotate encryption and
remove previous device access. Keep both copies during key replacement until
coverage is complete.

The private recovery secret and copied ciphertext suffice for offline decryption;
protect the copy separately from your devices. It cannot restore Apple Account
access or missing cloud data. Account-loss recovery requires a separately exported
backup; backup restoration is outside this feature. Physical-device acceptance
and cryptographic review remain pending.

The recovery dialog first checks this device’s existing key. If it can already
open your vaults, the dialog confirms that access is working and disables recovery.
Closing setup or recovery clears the offline copy from the session without locking
the app. Explicit locking and normal security locking still clear recovery access.

### Test recovery without a spare device

In **Settings → Recovery → Set Up or Verify Recovery…**, expand **Test recovery
on this device**. Import your saved offline copy, then choose **Reset This Device
for Recovery Testing…**. After confirmation and successful verification, the app
clears this device's iCloud vault keys and cached iCloud data and opens recovery.
Local-only vaults and the vaults stored in iCloud remain intact. You must re-enter your offline copy to regain access.

For both the removed-device test and the single-device reset, follow the
[recovery testing procedure](OFFLINE-RECOVERY.md#testing-with-your-existing-devices).
Keep other enrolled apps locked or closed. Completing recovery preserves their
existing access.
