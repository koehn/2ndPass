# 2ndPass macOS UI/UX review — September 26, 2026

Reviewed source at `9ce147d`, the preceding UI revision, UI tests, and the running Mac app's locked window. The live window confirmed the contradictory locked/busy presentation described below. Enrollment, editing, recovery, and AutoFill findings are based on source inspection; real-device end-to-end behavior, VoiceOver, and visual layouts in those states still need acceptance testing. No credentials or access settings were changed. This is a product review, not a cryptographic audit.

2ndPass has a useful native foundation: NavigationSplitView, a real Settings scene, LocalAuthentication, native credential-provider integration, Recently Deleted, local password generation, and field-specific copy feedback. The largest problems are inconsistent state presentation and workflows that expose internal protocols. The latest architecture is substantially simpler than parts of its interface suggest.

Priority meanings: P1 = fix before considering the experience polished or dependable; P2 = important usability/platform improvement; P3 = refinement. Source references below use paths relative to the repository and line numbers from the reviewed revision.

## Locking, authentication, and privacy

### 1. P1 — Give locked state an explicit Unlock action

The toolbar and Vault menu always offer Lock. The locked detail tells people to use Refresh, and the item list independently says it is locked. In the observed live state Refresh was disabled, the status read “Vaults available,” and a spinner appeared. A person cannot tell whether to wait, authenticate, or repair a connection.

Use one coherent locked presentation, preferably across the content/detail area: “2ndPass is locked,” a primary Unlock button, and a short explanation. Return activates Unlock; show Touch ID-specific wording only when that capability is available. Swap toolbar Lock for Unlock or disable Lock while already locked. Keep Refresh for fetching current cloud data. Distinguish waiting for system authentication from fetching vault contents and from idle locked state.

Evidence: `Sources/MopUI/PlatformViews.swift:33`, `MopScenes.swift:43`, `ContentView.swift:122`, `ContentView.swift:142`, `AppModel.swift:584`.

### 2. P1 — Explicit locking and cancellation should remain deliberate choices

`lock()` blocks automatic unlock, but `activity()` clears that block. The Mac activity monitor includes mouse movement and scrolling. Inactivity expiry also clears the block and immediately schedules automatic unlocking when active. This can turn locking or dismissing authentication into another authentication prompt without choosing Unlock. It does not bypass authentication; it makes authentication intent unpredictable.

Model launch authentication, explicit lock, timeout, cancellation, and repair as distinct states. Permit one optional launch prompt; require an explicit Unlock after manual locking or cancelling. Timeout should leave a stable locked screen. Ordinary pointer activity can extend an existing session without starting a new one.

Evidence: `AppModel.swift:126–166`, `AppModel.swift:507`, `AppLifecycle.swift:39`. Existing test `cancelledAutomaticAuthenticationWaitsForInteraction` codifies generic activity retry and should change with the intended behavior.

### 3. P1 — Conceal password editors when the Mac app becomes inactive

Editing loads existing passwords into the draft, then renders them with a plain TextField. `deactivate()` clears the separately revealed value but does not conceal the loaded draft or its field. Unlike the generator and OTP view, the password editor has no inactive-state presentation guard. That contradicts Settings' promise that switching apps conceals secrets.

Default to a secure editor with an explicit reveal control. Immediately mask secret-bearing editors when inactive, without destroying the draft. Keep the existing immediate lock behavior on sleep/system lock. Do not make security transitions wait for a save dialog.

Evidence: `AppModel.swift:404–435`, `AppModel.swift:488`, `ItemDetailView.swift:312–325`, `MopScenes.swift:131`. Reproduce with a disposable login; this issue was established from code, not by revealing a real password.

### 4. P2 — Separate session, sync, and operation status

One status string and global busy flag serve many unrelated activities. The status is confined to the detail pane although its meaning is app-wide. Owner enrollment checks call `perform`, setting busy and clearing notices; controls across the app are disabled during that operation. Slow iCloud checks can repeatedly interrupt browsing.

Use independent session state, connection state, and operation state. Keep background discovery/enrollment quiet and allow browsing already loaded catalogs. Disable only controls that conflict with an in-flight operation; retain the service's write serialization. Show actionable offline/error status in a consistent app-wide location. Put technical diagnostics behind Details.

Evidence: `ContentView.swift:162`, `AppModel.swift:546`, `AppModel.swift:826–901`.

## First launch and device enrollment

### 5. P2 — Reduce setup to one primary next step

Creation exposes Create, Connect, Set up recovery, Recover, and Done at once. The device-key explanation and optional recovery setup compete with the user's immediate task.

After successful discovery, show either Create Your First Vault or Connect This Mac. Name the default “Personal.” Keep recovery available through a secondary “More options” route, and offer a nonblocking recovery/device checklist after the first successful setup. Retain the warning about losing the only authorized device, but express it in user terms. Discovery failures must remain errors rather than pretending no vault exists.

Evidence: `AppSheetView.swift:17–43`, `AppModel.swift:584–623`.

### 6. P1 — Make enrollment progress truthful

The joining screen shows an indefinite “Connecting through iCloud…” spinner whenever no rejected exchange is present. That condition also holds when polling is paused, authentication fails, or there are no vault IDs. The model already records last attempt, last successful contact, and paused state, but the view does not expose them. Restart and Cancel receive the same visual weight as the normal path.

Render explicit states: contacting iCloud, waiting for another unlocked device, paused/offline, connected, cancelled, and failed. Animate only while work is active. Show a relative last-checked time and an actionable Retry for failures; place Restart in troubleshooting. Dismissal should clearly mean either “continue later” or “cancel this request.” Support per-vault progress when connecting several vaults; currently selection can initiate requests for all unenrolled vaults while the status represents one.

Evidence: `AppSheetView.swift:91–122`, `AppModel.swift:819–923`.

### 7. P1 — Remove conflicting ownership and approval language

An unenrolled vault is labeled “Not owned by this account,” although same-account discovery is exactly how automatic enrollment starts. The main pane says an owner must approve the device; the connection sheet says no approval is needed. Completion still says “Approved.” These are different mental models for the same path.

Use “Not connected to this Mac,” “Open and unlock 2ndPass on another connected device,” and “Connected. Opening your vault…”. Reserve explicit approval language for sharing across accounts. Replace “Tap” with “Choose” or platform-specific “Click” in Mac-facing instructions.

Evidence: `AppModel.swift:540`, `ContentView.swift:96`, `AppSheetView.swift:99`, `AppModel.swift:837–886`.

### 8. P2 — Make the owner experience about identifiable devices

“Add my device” is an instruction screen, but also includes manual iCloud checking. Successful enrollment produces a generic “A new device has been added” notice. Settings displays a full UUID under every device and has a manual refresh button.

Present “Connect Another Device…” as brief instructions, then update Devices automatically. A completion notice should identify the device and relevant vault, with Review Devices. Use names and platform icons as the default identity; retain stable identifiers in Details. Device removal should name affected vaults, explain partial failures and last-owner constraints, and make removing this Mac unmistakable. The existing explicit Reconnect requirement after removal is worth retaining.

Evidence: `AppSheetView.swift:45`, `MopScenes.swift:65–81`, `MopScenes.swift:162`, `AppModel.swift:871–879`. Additional friendly metadata may require model/service changes.

## Navigation, settings, and sheets

### 9. P2 — Keep the three-column structure, reduce its chrome

The 260–340-point sidebar has a large branded header, a custom disclosure header, a plus button, and an ellipsis per vault. Items has a separate in-content title and plus button. The detail repeats vault context. At smaller widths these consume substantial space before the actual password fields.

Use native sidebar sections and a compact vault list. Remove the redundant 2ndPass wordmark inside the sidebar; the app/window already identifies itself. Put New Item in the toolbar and File menu, keep vault actions in a contextual menu, and use a clear Vault Details destination. Avoid forcing all columns visible whenever width crosses 950; respect a user's chosen collapsed state. Treat exact widths as visual-validation decisions, not hard-coded design rules.

Evidence: `ContentView.swift:33–89`, `ContentView.swift:176–180`. The live locked window confirms the duplicated chrome and empty columns.

### 10. P2 — Separate app preferences from vault management

Settings is a fixed-height 640-point-wide grouped form containing inactivity, devices, a vault picker, rename/delete/export, checkpoints, membership, sharing, recovery, developer options, and open-by-UUID. Opening it also loads devices, and changing its vault picker changes main-window selection through `prepareVaultAction`.

Use native Settings categories such as General, Security, AutoFill, Devices, and Advanced. Keep vault-specific actions in Vault Details anchored to a stable target. Avoid changing the main browser selection merely to inspect preferences. Replace the one-minute-at-a-time inactivity stepper with a compact duration picker plus a custom option. Capitalize Devices and Vault consistently. Do not authenticate merely to inspect unrelated preferences; load protected sections when requested.

Evidence: `MopScenes.swift:55–159`, `AppModel.swift:282–296`, `AppModel.swift:760`.

### 11. P1 — Restore conventional sheet actions and keyboard behavior

The latest revision replaced a bottom Cancel/primary-action row, default-action Return, and Escape with scattered action buttons and a generic Done button. Done is ambiguous on an unfinished Create, Rename, or Recovery form. All sheet content and dismissal are disabled while busy, even if the wait is for iCloud.

Use a fixed sheet footer: Cancel on the left of the trailing action group, a specific primary action on the right, Return for that action, and Escape for cancellation. Keep it visible while content scrolls. Make errors inline and preserve inputs. For already-submitted irreversible operations, explain that closing the presentation cannot undo submission; do not label dismissal as rollback.

Evidence: `AppSheetView.swift:15–86`; confirmed regression in the diff from `6fd9707` to `9ce147d`.

### 12. P2 — Complete the Mac command surface

Custom commands currently provide New Item, New Vault, Refresh, and Lock. Add Find, Edit Item, Move to Recently Deleted, Restore, and appropriate copy actions to menu commands with contextual enablement. Use Command-F to focus search and Return to act on the selected AutoFill result. Keep existing Command-N, Command-S, Command-comma, and lock shortcut. Ensure focus rings, full keyboard access, and VoiceOver work without hovering.

Evidence: `MopScenes.swift:43–53`, `ItemSearchView.swift:14–29`, `ItemDetailView.swift:129–137`, `CredentialProviderViewController.swift:265–310`.

## Browsing and editing

### 13. P1 — Protect edits during navigation

Changing selected rows calls `cancelItemEditing`; switching sections or vaults also clears the draft. A caption advertises this loss rather than preventing it. This is particularly painful when changing a password in a browser and returning to 2ndPass.

On ordinary navigation, offer Save Changes, Discard Changes, or Cancel, or retain an in-memory draft with explicit lifecycle rules. Mask rather than discard on ordinary Mac app switching. Security lock must still clear sensitive UI immediately. Preserve unsaved values through recoverable save/conflict errors and provide a review/retry path.

Evidence: `AppModel.swift:260–279`, `AppModel.swift:495`, `ContentView.swift:197–201`, `ItemDetailView.swift:83`.

### 14. P2 — Unify search behavior

Active items use a custom floating search-results overlay while the underlying list remains unfiltered. Choosing a result clears the query. Recently Deleted uses native searchable and actually filters its list. There is no explicit Find command.

Use a native search field and filter the main list, with the matched field as secondary text. Keep the query until cleared and show the scope and result count. If quick-jump suggestions are retained, make them an optional supplement with complete keyboard navigation. Keep secret values excluded from search.

Evidence: `ItemSearchView.swift:11–83`, `AppModel.swift:174–202`, `RecentlyDeletedView.swift:19`.

### 15. P2 — Simplify item detail and make field actions discoverable

Each field is a padded rounded card with separate reveal, hover-only copy, and dropdown actions. All displayed text has selection disabled and click-to-copy behavior, including notes. “Open website” is buried in the field menu. The large title, type label, and two AutoFill diagnostics take space before fields.

Use denser, aligned native rows or grouped sections. Make Copy reliably discoverable and keyboard-accessible; keep Reveal for secret fields. Let nonsecret notes/text support normal selection and Command-C. Offer a direct open-website affordance. Keep field-specific copied feedback, adding “clears in 30 seconds” for secrets where useful. Avoid making every login show an alarming Code AutoFill warning simply because it has no optional OTP field.

Evidence: `ItemDetailView.swift:31–75`, `ItemDetailView.swift:225–286`, `ItemDetailView.swift:329–375`, `SecretClipboard.swift:18–68`.

### 16. P1 — Make AutoFill repair instructions achievable

Exclusion messages tell people to change existing field types or rename a primary field to `username`, `password`, or `otp`. The editor only renders path/type controls for fields that are new and not template fields. A user cannot directly perform the requested repair on an existing custom field.

Expose safe field type/name editing, or a dedicated primary-credential mapping with clear validation. Prefer “Use for AutoFill” over requiring magic field names. Show only relevant, actionable eligibility problems; distinguish optional code setup from a broken login.

Evidence: `Sources/MopAppSupport/AutoFill.swift:32–78`, `ItemDetailView.swift:181–190`.

### 17. P2 — Refine generation and validation

Local generation, strength feedback, explicit Use Password, and concealed OTP seeds are good choices. The 420-point-wide, potentially 600-point-tall generator is large for a popover; password length uses a long-range stepper. Disabled Save/Create actions often lack an explanation outside OTP validation.

Use a compact generator with a length entry/slider, grouped options, Regenerate, and Use Password. Show name/path/duplicate-field errors beside their controls. Retain explicit save semantics and distinguish strength estimation from breach detection. Use grouped verification-code digits and a restrained countdown; avoid relying on red/green alone (the existing numeric countdown helps).

Evidence: `PasswordGeneratorButton.swift:39–69`, `PasswordStrengthView.swift:22–42`, `ItemDraft.swift:72–78`, `ItemDetailView.swift:391–419`.

### 18. P2 — Give empty, deleted, and offline states useful actions

An empty vault gets “No items.” Recently Deleted's locked explanation promises automatic authentication. Offline mode has technical cache timestamps and broadly disabled editing. One failing connected vault clears the whole unlocked catalog set.

Offer Add Your First Login on a truly empty vault and a distinct No Search Results state. Keep deletion expiry visible, offer Undo after moving an item to trash, and preserve restore conflict guidance. Use “Offline — changes unavailable” with a relative last-sync time and a retry action. Consider per-vault availability so an unavailable vault does not conceal independently authorized healthy ones; this requires explicit security/state design, not merely suppressing errors.

Evidence: `ContentView.swift:121`, `RecentlyDeletedView.swift:21–55`, `AppModel.swift:660–668`.

## AutoFill

### 19. P1 — Add provider setup and publication health

There is no AutoFill section in Settings or a guided enablement step. The app displays “fields ready,” which only proves schema eligibility. Publisher state is checked internally, but its enabled state is not shown, and publication failures are suppressed with `try?` at the service call site.

Add Settings > AutoFill: provider enabled/disabled, instructions or a supported route to system settings, last successful suggestion update, and Refresh Suggestions. Do not fail a successful vault save because publishing failed; show a separate recoverable AutoFill status. Explain once that website/username metadata appears in system suggestions while filling requires authentication.

Evidence: `MopScenes.swift:55–149`, `ItemDetailView.swift:60–72`, `Sources/MopAppSupport/AutoFill.swift:189–207`, `NativeVaultService.swift:59–60`.

### 20. P2 — Improve the credential picker without expanding metadata casually

The picker sorts exact-host matches first but does not label them. It shows only website and username, so two credentials with identical website/username from different vaults are visually indistinguishable. No-results search yields an empty list rather than an explanation. Search has no explicit initial focus or selection/Return handling.

Use sections such as “For this website” and “Other accounts,” a visible selected row, keyboard navigation, Return to fill, Escape to cancel, and a no-results state. Address ambiguity with a deliberate privacy decision: either authenticate before showing encrypted item/vault labels, or explicitly approve a minimal additional metadata label. Do not silently publish item titles or vault names. Show the requested site's context before choosing an unrelated account.

Evidence: `CredentialProviderViewController.swift:84–90`, `CredentialProviderViewController.swift:265–310`, `Sources/MopAppSupport/AutoFill.swift:95–124`.

### 21. P1 — Provide actionable AutoFill failure recovery

A selected-credential failure can leave a small 360×140 presentation with a message and Cancel, without Retry or Choose Another Account. Picker errors and empty states repeatedly direct the user to open/unlock 2ndPass. That route itself lacks a clear Unlock button. Different failures collapse to “credential unavailable.”

Keep fresh authentication for each fill; that is the current security policy. Improve surrounding UX with distinct cancelled, removed/stale, unconfigured, and unavailable states, a safe Retry, and Choose Another Account where supported. Use an Open 2ndPass route only where the extension platform supports it; otherwise give precise instructions. Let error content expand beyond the compact progress size. Keep code generation after authentication and reject expired results; offer retry rather than filling stale codes.

Evidence: `CredentialProviderViewController.swift:175–180`, `CredentialProviderViewController.swift:222–233`, `docs/AUTOFILL.md`.

### 22. P2 — State the supported AutoFill scope clearly

Existing passwords and verification codes work through native provider APIs. Passkeys, saving new credentials, and generating a password directly in AutoFill are not implemented. Make this scope clear in setup/help so missing capabilities do not look broken. Treat those capabilities as future product work, not leftovers to remove.

Evidence: `docs/AUTOFILL.md:Storage and refresh`, credential-provider entry points.

## Sharing, recovery, backups, and destructive actions

### 23. P2 — Replace protocol forms with guided tasks

Sharing/recovery uses a Step picker, generic Continue, JSON import/paste, account/device UUID input, a zone-owner field, and full fingerprint entry. These are valid protocol operations but a difficult consumer interface. Recovery presents multiple requests and fingerprints at once. Continue is not gated on most required inputs. File chooser cancellation is caught as an error.


### 24. P2 — Make backups and deletion native and legible

Export asks for a folder via a file importer and chooses a random filename. Its error says “Choose a writable folder in Files” on Mac. Vault deletion prominently shows a UUID but does not itself display a clear friendly target name or offer a backup. Field deletion uses “Delete secret,” while item deletion uses Recently Deleted.

Use a native save presentation with a readable vault/date filename and maintain exclusive/no-overwrite guarantees. Show destination and Reveal in Finder after success. If keeping a folder chooser, label it explicitly and handle cancellation silently. In vault deletion, display the vault name and irreversible scope, offer Export Backup, then require the intended confirmation. Use “Move to Recently Deleted” for items and “Delete Field” for fields; do not imply that field deletion has item-level recovery. Bind destructive sheets to an immutable target so another window cannot change what is being confirmed.

Evidence: `DocumentTransfers.swift:28–39`, `AppModel.swift:1075–1090`, `AppSheetView.swift:69–76`, `ContentView.swift:213–220`.

## What to remove or retire

| Element | Disposition | Evidence/reason |
| --- | --- | --- |
| “Legacy · UUID” vault fallback | Replace with a neutral unnamed/unavailable vault label | `AppModel.swift:452`; v6 does not display/convert old formats, and open-by-ID deliberately creates a nil-name descriptor. |
| “Not owned by this account” for unenrolled vaults | Remove this interpretation | `AppModel.swift:542`; connection state is not ownership. |
| Manual owner approval language in same-account connection | Remove/replace | `ContentView.swift:96`, `AppModel.swift:886`; automatic flow supersedes it. |
| Same-account confirmation/approval/rejection view-model methods | Remove after caller check | `AppModel.swift:925–950`; no current UI/test callers found. Preserve protocol/CLI functionality where still required. |
| `EnrollmentFlow.addDevice` manual exchange branch | Remove unused UI branch | `SharingView.swift:16,59,106,145`; actual Add My Device uses CloudEnrollmentView, no `flow: .addDevice` caller found. |
| Unreachable `.trust` sheet | Retire from the normal UI enum/view unless a deliberate diagnostic entry point is added | `AppSheetView.swift:60`; no route sets this sheet. Do not remove checkpoint validation from recovery. |
| Old “Waiting for your 2ndPass identity” UI-test expectation | Update | `Apple/UITests/MopUITests.swift:340` contradicts the current device-local enrollment error text in `MopError.swift:81`. |
| Manual same-account enrollment request/accept entries in Advanced | Move out of ordinary settings; retain only if a supported diagnostic workflow needs them | `SharingView.swift:65–68`; overlap with automatic connection and cross-account joining. |
| Top-level Show Checkpoint and Verify Members buttons | Move into Security Details/Advanced | `MopScenes.swift:91–98`; raw hashes/IDs should not be normal housekeeping. |
| Duplicate Remove Device path accepting a UUID | Consolidate around the device list; retain explicit per-vault administration if needed | `SharingView.swift:69–72,88`; account-wide and per-vault scopes must remain clear. |
| Repeated branding, permanent success badges, generic Done buttons | Remove or replace as described above | Redundant chrome, optional-OTP noise, and ambiguous form completion. |
| QR pairing, Add Mobile Device, strict-biometrics setting, recovery-key-export gate, separate Vault Settings sheet | Already removed; do not report them as current UI | History and current view graph confirm their removal. Keep regression coverage for retired flows. |

Also update `docs/ACCOUNT-IDENTITY.md`, which still describes manual same-account invitation/owner approval, and the enrollment diagnostics/restart paragraphs in `docs/GUI.md`, which describe comparison/confirmation UI and request metadata no longer rendered. These docs should describe the same flow as the product.

## Suggested delivery order and acceptance

1. **Behavioral consistency:** explicit Unlock, stable lock/cancel states, inactive password-editor concealment, edit preservation, truthful enrollment progress, actionable AutoFill repair. Test with fake clocks/network failures and disposable secrets.
2. **macOS structure:** native sheet footers and keyboard commands, Settings categories, Vault Details, native search, compact field rows, contextual status.
3. **Guided setup:** simplified creation, identifiable device notices, separate sharing/recovery flows, AutoFill setup and refresh health, backup polish.
4. **Cleanup:** remove the confirmed unreachable/redundant UI paths and align tests/documentation. Do not remove security verification merely because its current presentation is too technical.

Acceptance should cover launch/cancel/retry, explicit lock followed by pointer movement, timeout while foregrounded, sleep/wake, switching apps while editing a password, navigation with unsaved edits, several vaults with one unavailable, enrollment offline/cancel/restart/expiry, recovery imports, device removal/reconnect, provider disabled/enabled, stale and ambiguous AutoFill entries, and TOTP rollover. Verify narrow/wide windows, light/dark appearance, increased contrast, reduced motion, full keyboard access, and VoiceOver on Mac.

The current UI automation fixture is enabled only under `DEBUG && targetEnvironment(simulator)` and the UI suite uses iOS-specific APIs. Add a Mac-capable fixture and Mac UI coverage before relying on those tests for desktop interaction correctness. No tests were run for this review; implementation was not changed.

Apple's current guidance supports the native split-view foundation, window toolbars, menu-bar access to commands, and respecting user window/toolbar configuration. The specific restructuring recommendations here are design judgments applied to 2ndPass, not claims that Apple mandates a particular layout. References: [Designing for macOS](https://developer.apple.com/design/human-interface-guidelines/designing-for-macos/), [Toolbars](https://developer.apple.com/design/human-interface-guidelines/toolbars?changes=la), [Sidebars](https://developer.apple.com/design/human-interface-guidelines/sidebars?changes=_11).
