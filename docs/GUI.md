# Native app

The SwiftUI Mac/iPhone/iPad app, CLI and AutoFill use the same v6 service and
device-local identity. Old-format vaults are not displayed or converted.

## Guided setup

Successful iCloud discovery with no v6 vaults opens **Create a vault**. Enter a
name (the displayed Personal default creates `personal`) and authenticate; Mop generates the device’s hardware keys and opens the
vault immediately. Recovery is optional and does not block creation. A notice
explains the risk of losing the only authorized device.

When iCloud contains v6 vaults that this device cannot access, **Connect this
device** opens instead. Selecting an unenrolled vault also opens that flow.
Discovery does not authenticate cloud data or create a local trust pin. Failed
CloudKit discovery reports an error rather than claiming the account is empty.

On your own new device, select the desired vaults and choose **Connect**. Mop generates keys and submits signed requests through
iCloud. An unlocked owner device processes it automatically without a dialog.
The new device shows progress and asks you to unlock Mop elsewhere if waiting.
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
Explicit approval remains necessary for cross-account sharing.

**Set up or replace hardware recovery** can be used after secrets are saved.
Generate the recovery request on a separate device and import it on an owner
device. This grants recovery access to existing contents. Adding recovery does
not change passwords; replacing recovery rotates current encryption keys.
Advanced access management retains member/device removal, role changes,
checkpoint import and cloud permission reconciliation.

## Items and sessions

The existing item editor supports typed fields, renaming, password-strength metadata, concealed values, TOTP, trash/restore and encrypted backup export. Catalog browsing opens its own key; revealing a password opens that record's key. Values passed to an edit are plaintext inside Mop. The catalog stores concealed fields without values.

Mop attempts authentication once at launch while active. After cancelling, locking,
inactivity expiry, or waking from system lock, choose **Unlock Mop** to authenticate.
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
refresh; Mop never silently overwrites another revision.

Explicit lock, inactivity expiry, system lock/sleep, account loss, device revocation,
and termination clear drafts and reject late results immediately. Security locking
never waits for an unsaved-changes dialog. Drafts are not persisted across lock or
restart; save important changes before leaving the session.

Offline browsing is explicit and read-only. It cannot establish remote freshness or revocation. The CLI and GUI share device-local app-group checkpoints; never synchronize their local state directory.

## Recovery

**Recover an existing vault** is also available from creation on a device with no local vaults. On the enrolled recovery device, import the encrypted backup, verify its checkpoint, and paste independently verified replacement owner/recovery requests. Return the resulting encrypted checkpoint to the replacement owner and use **Import trusted checkpoint**. Lost-account recovery creates a new UUID/root under the current account and retains the source; the replacement owner request must belong to the recovery device's ordinary identity under that new account.

If all authorized and recovery device keys are gone, neither a backup nor account restoration is sufficient. Keep the recovery device separate. [Validation](VAULT-NEXT-VALIDATION.md) lists remaining physical acceptance, including second-account sharing and actual iOS/AutoFill hardware.

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

After creation, a dismissible checklist offers another device, hardware recovery,
and AutoFill setup. Sharing/recovery remain separate tasks under More Options.

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

## Settings and Vault Details

Open **Mop → Settings…** (Command-comma) on Mac, or the Settings gear on iPhone
and iPad. Security, AutoFill, Devices, and Advanced are separate categories. Mop
remembers the last category. Security offers inactivity presets and a custom
minute value. Opening Settings neither selects a vault nor authenticates.
Devices loads protected information only while unlocked.

Use **Vault Details** in the toolbar or a vault’s context menu for rename,
backup, sharing, hardware recovery, and deletion. Details appears in the main
pane and returns to the previously selected item. Checkpoints, membership, and
advanced access operations are under Security Details. Leaving a modified item
uses the same Save Changes, Discard Changes, or Cancel decision as navigation.

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
