# Native Mac app

`MopApp` is a SwiftUI companion to the CLI. The signed `Mop.app` opens the native
window; `Contents/MacOS/mop` remains the CLI used by the installer and shell.
Both executables use the same signing identity, application-specific Keychain
group, CloudKit container, and existing local device state. Version 0.5 requires fresh named vaults; legacy cloud data remains untouched.

## Build and open

```sh
swift build
swift test
# Set the signing variables documented in README.md, preserving your existing ID
# and CloudKit environment when upgrading.
scripts/package.sh
open dist/Mop.app
```

`swift run MopApp` can exercise the unsigned app shell, but actual vault access
still requires the provisioned bundle. Packaging includes and explicitly signs
the CLI helper before signing the enclosing application. The helper verifies its
own signing requirements and the enclosing bundle's seal. The existing installer
continues to create a symlink to `Contents/MacOS/mop`.

## Workflows

- Opening the app discovers your vaults and prompts once to unlock enrolled vaults.
  Cancelling leaves the app locked without repeatedly prompting. The sidebar has
  **All Vaults** and a collapsible **Vaults** list. All Vaults combines items while
  showing their vault names; same-named items remain separate. Select a specific
  vault before creating items or managing that vault. Unsupported and unenrolled
  vaults stay in the sidebar for explicit management rather than being opened.
- Find named vaults, select by name, or create a new vault. UUIDs remain visible in details and can be entered explicitly. New vault
  creation saves the recovery credential first and displays the vault and device
  fingerprints. Move the recovery key offline. Creation failures retain the key
  and selected UUID for reconciliation; do not blindly repeat initialization.
- Unlock the encrypted index to browse items and their fields in saved order, with optional section labels. Copying a
  reference does not decrypt the secret. Reveal, copy-value, create, replace,
  delete, and management operations use the current native authenticated session.
- Secret values pass directly to the native vault libraries, without subprocesses. Reveal
  and concealed clipboard values expire after 30 seconds. Clipboard clearing checks the
  pasteboard change count so another application's newer content is retained.
  Secret copies are restricted to this Mac and carry a confidential-content
  marker for cooperative clipboard managers. Revealed values do not allow native
  text-selection copying; use **Copy value** to apply the field’s clipboard policy.
  Switching apps conceals revealed values but leaves the window visible and allows the copied value to be
  pasted until its timer expires. Explicit lock, sleep, and session deactivation
  also clear Mop’s concealed clipboard entry. Non-concealed copies (such as usernames,
  websites, and notes) have no timer and are not cleared by locking. Clipboard history
  tools may retain copies.
- Enable **Offline snapshot** explicitly and select a vault (or enter its UUID).
  Authenticated reads show the verified snapshot's timestamp. Editing and device
  management are disabled. Synchronizing ciphertext alone does not authenticate
  or update the verified offline snapshot.
- Use **Trusted Macs** to authenticate the device list and review enrollment
  requests. Approval requires an independently obtained fingerprint, not merely
  accepting the displayed public request. Removal rotates keys and displays the
  new vault fingerprint for verification on remaining Macs.
- **Each vault’s three-dot menu** supports enrollment requests, vault trust, recovery from an
  offline credential, and encrypted backup export. Recovery-key and backup file
  writes preserve the CLI's protected-path and no-overwrite checks.

The app owns one authenticated device context for all enrolled vaults opened during
its session. Vaults open lazily; switching vaults does not prompt again. Online
sensitive operations refresh the cloud snapshot and check account, enrollment,
trust, and revision conflicts. Network errors never silently select offline data.

**Mop → Settings…** configures 1–60 whole minutes of GUI inactivity, default 5.
Keyboard and mouse activity in Mop resets the timer; background work and use of
other apps do not. Shortening the timeout applies against the last activity.
Switching apps leaves metadata, editor drafts, and sheets visible
and conceals revealed values, while retaining the session. Returning checks the
session deadline. Reveal/copy requests that lost focus discard
their value even if focus returns before completion.

Manual Lock (Command-Shift-L), sleep, Mac session locking, quitting, account changes,
and switching online/offline mode invalidate authorization. Lock clears catalogs,
editor drafts, and owned concealed clipboard contents. Authentication or operation results
arriving after lock cannot reopen the UI. An already submitted mutation may still
commit; use **Sync** to reconcile uncertain results before retrying. A subsequent
native operation also reconciles through its snapshot refresh. Context failures
require explicit unlocking again. Secrets are not saved to preferences or logs.

The GUI honors `MOP_STATE_DIRECTORY` and constrains native operations to the selected UUID.
`MOP_CLOUD_VAULT` no longer selects a vault. The GUI also ignores obsolete
`MOP_VAULT_FILE`. The CLI can import encrypted v4 backups; legacy file vaults
are no longer supported and have no migration path.
CloudKit access requires the same signed-device validation described in
[VALIDATION.md](VALIDATION.md). Automated GUI tests use injected services, clocks, authentication, and in-memory
cloud transports; they do not replace Touch ID, signed two-Mac enrollment, or
production acceptance tests.

File import and historical revision restoration remain CLI workflows in this
version. The app deliberately has no shell/command runner.

## Named vault and item actions

The Vault picker displays discoverable names. These names are visible to CloudKit;
item and field names remain encrypted. **Rename vault** authenticates and commits
the new name, preserves UUID selection, and refreshes the catalog within the current session. Update
all scripts and configuration using the old name: aliases are not retained.

**New item** starts from a Login, Password, API credential, Secure note, Database,
or Custom template in the inline detail editor. Choosing another template replaces
untouched blank fields, or adds missing fields while preserving entered values.
Select an item and use **Edit item** to edit its field cards directly in the detail
pane. The Edit item button sits beside the vault/item breadcrumb. Add/remove custom
fields and drag the handles to reorder them. New custom fields offer a type picker;
saved fields omit type labels. Template fields have fixed names and cannot be removed.
Control-click a handle for Move up/Move down; the same actions are available to
VoiceOver. Save commits values, metadata, and field order atomically; Cancel leaves
the saved item unchanged. The item name becomes an inline text field while editing.
Renaming atomically updates all its references without decrypting untouched secrets;
existing field paths remain fixed. References using the previous item name must be
updated. A name already used in that vault is rejected. **Add field** also opens this inline editor.

Hover over a field to show **Copy**. The trailing dropdown provides **Edit value**,
**Reveal/Conceal**, **Copy value**, **Copy reference**, and **Delete field**. Reference
URLs are available through Copy reference rather than displayed under every field.
Copy is also available through keyboard focus and the dropdown.

**Edit value** turns just that value into an inline input with Save and Cancel.
Password fields load the current password into a cleartext input. OTP and other
concealed fields use masked replacement inputs; notes use a multiline editor.
Visible values are prefilled. Unchanged passwords and other concealed values keep
their stored records. Delete the input text to save an empty value.

Drafts retain the revision they were opened from, so a concurrent change produces
a conflict rather than overwriting it. Failed saves retain the draft for review.
Leaving the item or locking Mop discards unsaved edits. Editor transitions and
reordering animate briefly and respect Reduce Motion; locking and concealing
revealed values remain immediate. **Delete field** retains its confirmation dialog.

Username, website, email, text, and notes values display after unlocking. Password,
OTP, and concealed values stay hidden until explicitly revealed or copied. All field
values remain encrypted on disk and in iCloud. Converting a concealed field to a
visible type requires opening its value and makes it available on subsequent index
unlocks. Existing untyped fields remain concealed. OTP stores a seed or `otpauth`
URL; code generation is not implemented. Upgrade all Macs before saving typed
items; older clients cannot decode the extended encrypted index.

Deleting the last field removes the item. Whole-item delete is not available.
Offline discovery uses verified cached snapshots only, so remote renames may not
be visible. Legacy vaults appear with their UUID and require an older client.

**Vault’s three-dot menu → Delete vault…** supports both named and legacy vaults. Type the
name, or the full UUID for an unnamed legacy vault, then authenticate to delete
all cloud contents/history and this Mac's vault data. The dialog fixes the target
UUID and explains that backups and other Macs' caches remain. Failure or uncertain
results retain the selected target for retry; an inactive or locked view does not
publish completion into a different context. Submitted deletion may still finish.

**Export backup…** is available in each vault’s three-dot menu and inside the delete dialog for
supported vaults. It uses native authenticated export, an NSSavePanel,
and the selected UUID. Offline export uses a verified snapshot. Existing output
files are not overwritten; select a new filename. Export is optional, and legacy
backups require an older client.

## Signed hardware session acceptance

Package with the existing signing identity and provisioning profile, then verify:

1. Set inactivity to 10 minutes. Unlock with Touch ID (and test password fallback
   separately on a non-strict device). Read, edit, and switch between enrolled
   vaults without another prompt. Keep interacting for more than five minutes and
   confirm subsequent reads still work without prompting.
2. Switch apps and return before expiry: values are concealed and the session is
   retained. Leave Mop idle through the deadline: returning requires authentication.
3. Lock manually during authentication, a read, and a submitted write. No late
   result restores data. A submitted write may require Sync to reconcile.
4. Test Mac screen lock, sleep, account changes, and online/offline switching;
   each ends authorization. Unlocking then prompts again. Verify strict biometric
   policy continues to reject password fallback.

These checks require the signed application and interactive Secure Enclave hardware;
a passing software suite alone does not establish them.

## Password quality

Password fields show a five-level estimated-strength indicator. Selecting an item
reads the rating saved in encrypted vault metadata, without decrypting password
records. Older unrated fields show Strength unavailable until a password is set again. New and edited
passwords update after a short typing pause. Scores and drafts are cleared on lock.

Estimation uses the pinned [native zxcvbn implementation](https://github.com/DeVitoC/zxcvbn-swift),
including its common-password dictionaries. Evaluation
uses at most the first 100 characters to bound computation. It never sends passwords
to a server and does not check breach databases. The packaged app includes the
estimator dictionaries and its MIT license; an estimate is not a security guarantee.

## Password generator

Password fields offer Generate password only while editing, including new-item forms.
Password inputs display cleartext while editing; saved values remain concealed.
Choose 8–128 characters, lowercase/uppercase letters, numbers, symbols, readable
characters (excluding similar glyphs), or pronounceable consonant/vowel sequences.
Pronounceable mode requires letters and appends a number and/or symbol when selected.
The preview shows a live quality estimate. Use password fills the input; Save commits
it. Cancel preserves the original value. Previews always display the generated password in cleartext and close when Mop
loses focus or locks. Generator settings are remembered locally between uses and
app launches; generated passwords are never stored in these preferences.

When adding a field while editing or creating an item, use Field type to select its
input type. Selecting Password enables the generator and live quality indicator.
The selected type is saved with the field.

Create a vault using the + button beside Vaults in the sidebar. Each vault row has
a three-dot menu whose actions apply to that vault, including from All Vaults.

Editing an existing password loads its current value into the cleartext input.
Edit item loads all of its password fields; Edit value loads only that password.
Unchanged loaded passwords preserve their stored records on Save. Failed reads
cancel the draft, and late reads cannot restore it after locking or cancellation.

The strength indicator uses the rating already present in the item catalog, including
when the stored password is loaded for editing. Only changed or newly entered
passwords are estimated live; restoring the original value restores its saved rating.

All templates include a multiline Notes field. Template field names are fixed, and
template fields cannot be removed through the editor or field menu. Their values
and order remain editable. Custom fields can still be added and removed.

Search matches item and vault names, field labels, and non-hidden field values
(including usernames, websites, email, text, and notes). Passwords, OTP seeds, and
other concealed values are excluded, and searching never reads secret records.

New item uses the same inline editor as Edit item. From All Vaults, its Vault picker
chooses among unlocked, enrolled vaults and remembers your selection locally for
next time. An unavailable remembered vault is ignored. Creating from a single vault
uses that vault without changing the All Vaults preference. Cancel and Lock discard
the draft; Save keeps the All Vaults view and selects the newly created item.

## Recently Deleted

Right-click an item in the item list and choose **Delete…**, then confirm. The whole
item moves to **Recently Deleted** in the sidebar and disappears from normal vault
lists, search, and All Vaults. This is a separate GUI area, not a new cloud vault:
each item keeps its source vault's encryption, enrolled Macs, and recovery key.

Select a deleted item and choose **Restore item**, or right-click it and choose
**Restore**, within 30 days. Restoration goes to its original vault and preserves
field values, order, templates, and saved quality ratings. If the original name is
already in use, rename that active item first. Offline snapshots are read-only.

Items expire after 30 elapsed days. Expired entries disappear from Recently Deleted;
Mop removes their records from the current vault snapshot during an online unlock or
refresh, and while an unlocked online session is idle between edits. Cleanup cannot
run while Mop is closed, locked, or offline. Historical encrypted cloud revisions
and exported backups retain their existing history; retention is not a guarantee
of erasing those copies. Use current Mop versions on all Macs: older clients do not
understand the deleted-item metadata.

Inactive Mop windows stay visible without a privacy cover. Revealed values still
conceal on focus loss, and generator popovers close. Unlocked catalogs remain in
memory across vault, All Vaults, and Recently Deleted navigation. Only unopened
vaults need an initial catalog load; Lock clears all catalogs and sessions.
Secret reads refresh cloud state to check revocation and conflicts, reuse the open
index when the snapshot is unchanged, and decrypt only the requested record. A
changed remote snapshot requires reopening its index; explicit Refresh updates
cached metadata.
