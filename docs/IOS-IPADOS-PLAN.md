# iOS and iPadOS application plan

Status: implementation reference. Shared application sources and build support are
implemented; see [MOBILE.md](MOBILE.md) for validation and remaining release gates.
Baseline: repository source and macOS GUI workflows inspected September 23, 2026.

Use one shared native SwiftUI interface across macOS, iPhone, and iPad wherever
Apple's technology permits. Ship all existing macOS GUI capabilities on both mobile
platforms; let the shared interface adapt its layout and presentation to available
space and platform conventions. Share vault implementation and interaction logic.
Keep the existing macOS application and CLI working throughout the project.

## Scope and defaults

- Start with iOS/iPadOS 18 as the proposed deployment minimum, subject to the
  dependency and SDK compilation gate below. This aligns with the existing
  macOS 15 baseline and use of Observation and Synchronization.
- Prefer an Xcode multiplatform app target supporting macOS, iPhone, and iPad,
  consuming local Swift package libraries and the same UI sources. Preserve the
  current macOS packaging and CLI-helper signing contract. The existing SwiftPM
  Mac executable may remain as a thin build entry point consuming that shared UI;
  separate build wrappers must not become separate interfaces.
- Reuse the existing CloudKit container, vault format, encrypted item schema,
  enrollment protocol, recovery credentials, fingerprints, and backup format.
  Each physical phone or tablet enrolls as its own device with its own key.
- Support one Mop window per mobile app initially, including iPad resizing and
  multitasking. Multiple simultaneous Mop windows are a separate enhancement;
  the Mac currently also uses a single main window.
- Treat Password AutoFill, passkeys, OTP code generation, widgets, share extensions,
  and Shortcuts as follow-up work. They are not present in the Mac GUI and are
  not required for parity. Preserve storage of OTP seeds and `otpauth` URLs.
- CLI-only commands, shell execution, backup import, and historical revision
  restoration do not become mobile requirements. Recovery-file selection does.

## Feature parity checklist

Use this table as the release checklist, covering both phone and tablet. Existing
restrictions, authentication requirements, and error behavior are part of parity.

| Capability | Required mobile behavior |
| --- | --- |
| Vault discovery and selection | All Vaults, named vaults, UUID selection, duplicate-name disambiguation, supported/legacy/unenrolled states, launch discovery and cancellable unlock |
| Vault creation | Name and device name, strict biometric option, recovery credential saved before cloud publication, device/vault fingerprints, retained UUID and recovery material after uncertain creation |
| Vault management | Rename, request enrollment, independently verify trust, display fingerprints, recover access, encrypted backup export, confirmed deletion including legacy vaults |
| Enrollment management | Authenticated device list, pending requests, independent fingerprint entry for approval, removal/key rotation, updated vault fingerprint |
| Browsing and search | Ordered fields and sections; search item/vault names, labels, and visible values without reading concealed records; distinguish same-named items across vaults |
| Item creation and editing | Login, Password, API credential, Secure note, Database, Custom templates; All Vaults destination picker and remembered selection; atomic rename and save; custom fields and field ordering |
| Field editing | Inline value editing, multiline notes, type selection for new fields, template name/removal restrictions, preserved untouched concealed records, empty values, revision conflicts, retained drafts after failed saves |
| Secret actions | Reveal/conceal, copy value, copy reference, confirmed custom-field deletion, no bypass of clipboard policy through selectable revealed text |
| Password tools | Saved strength ratings, bounded local estimation for changed values, full generator options and remembered preferences, cleartext editing/preview consistent with Mac behavior |
| Recently Deleted | Confirm whole-item deletion, original vault/name and dates, 30-day retention, restore with collision handling, no secret reveal before restoration, online purge and offline restrictions |
| Online and offline | Explicit read-only verified snapshots with timestamps, ciphertext sync distinct from authenticated verification, no silent fallback on network failure |
| Session controls | Manual lock, unlock/refresh, 1–60 minute inactivity setting (default 5), account-change invalidation, stale-result suppression, safe handling of uncertain writes |

The current source includes whole-item deletion and restoration. An earlier
paragraph of `docs/GUI.md` says whole-item deletion is unavailable; use the source
and the document's newer Recently Deleted section as the baseline.

## One adaptive interface using Apple's APIs

Apple explicitly supports a single multiplatform target and shared SwiftUI `App`
structure for iOS, iPadOS, and macOS. Adopt that direction; retain conditional
scene/configuration declarations only where required by desktop packaging or API
availability. See [Configuring a multiplatform app](https://developer.apple.com/documentation/xcode/configuring-a-multiplatform-app-target).

The existing `ContentView` already uses a three-column `NavigationSplitView`.
Refactor it into one shared `MopRootView`, rather than build a second mobile
navigation shell. SwiftUI automatically collapses these columns into a stack at
compact widths, including iPhone and narrow iPad layouts. Use selection-bound
`NavigationLink`s and shared navigation state so taps and programmatic selection
both navigate correctly. Test explicit transitions for new items, restoration,
All Vaults, and lock; desktop list selection alone is not sufficient evidence of
compact-navigation correctness. See [Apple's navigation guidance](https://developer.apple.com/documentation/technotes/tn3154-adopting-swiftui-navigation-split-view).

| UI concern | Shared implementation and permitted adaptation |
| --- | --- |
| Navigation | One `NavigationSplitView`, sidebar, item list, detail, and selection model. Control column visibility/compact preference as needed; do not maintain phone-only routing. |
| Item detail and editing | The same field cards, inputs, editor, Save/Cancel actions, validation, and ordering on every platform. Detail naturally occupies the full width when navigation collapses. |
| Administration and generator | Shared forms and `.sheet`/`.popover` content; adjust presentation sizing and compact adaptation only. |
| Toolbars and menus | Shared action definitions using SwiftUI `ToolbarItem`, `Menu`, and semantic placements. The system supplies platform presentation; conditional placement/styling is allowed where necessary. |
| Settings | One `SessionSettingsView`, hosted in the Mac `Settings` scene and a mobile settings destination/sheet. |
| File selection/export | Prefer common `.fileImporter`/`.fileExporter` presentation on every platform, backed by the same export/recovery workflow. Use a native adapter only if a tested security or completion requirement cannot be met. |
| Layout | Flexible frames and shared responsive layout; use `ViewThatFits` or `Layout` where needed. Avoid separate device-specific copies of forms. |
| Pointer, touch, accessibility | Always expose explicit shared action buttons/menus. Hover, context menus, keyboard commands, and gestures are additive affordances over the same actions. |

SwiftUI [toolbars](https://developer.apple.com/documentation/swiftui/toolbars) adapt
their presentation to platform and context. Apple's shared
[file dialog options](https://developer.apple.com/documentation/swiftui/filedialogbrowseroptions)
also distinguish native iOS and macOS behavior behind the common importer/exporter
modifiers. Availability-check newer enhancements against the proposed iOS 18 and
macOS 15 minimums rather than raising deployment targets incidentally.

Share command definitions wherever available. Apple's current
[menu bar guidance](https://developer.apple.com/documentation/swiftui/building-and-customizing-the-menu-bar-with-swiftui)
covers both iPadOS and macOS; newer iPad menu-bar behavior must be availability-gated.
Keep all operations accessible through shared on-screen controls on older systems.

The following are acceptance descriptions of that same interface at different
sizes, not instructions to implement separate view hierarchies.

### iPhone

- Let the shared split view collapse to vaults/All Vaults → item list → item detail.
  Recently Deleted, per-vault Trusted Devices, and Settings remain directly
  reachable from the root and vault menus.
- Put New Item, search, refresh, and Lock in visible navigation/toolbar actions.
  Use labeled overflow menus for less frequent vault operations.
- Show field actions through an explicit button and menu. Long-press and swipe
  actions may supplement buttons, but cannot be the only way to perform an action.
- Present the shared item editor full-width with Save/Cancel; use shared sheets for the generator and
  management forms. Keep the target vault and item visible during editing.
- Use native field-reordering controls plus accessible Move Up/Move Down actions.
  Preserve the existing draft and revision semantics across presentation changes.

### iPad

- Show the shared three-column `NavigationSplitView`: vaults, items, detail.
  Allow its automatic collapse in narrow windows without losing selection or drafts.
- Retain inline detail editing, with adaptive sheets/popovers for management and
  generation. Avoid fixed desktop minimum widths.
- Support pointer interaction, hardware keyboard focus, Command-N, Command-R,
  Command-Shift-L, Escape/Cancel, and accessible reorder actions.
- Test rotation, software-keyboard presentation, Split View, and resizable windows.
  Resize must not submit, discard, or accidentally reveal a draft.

Both layouts need Dynamic Type, VoiceOver labels and announcements, sufficient
touch targets, Reduce Motion, light/dark appearances, and explicit loading,
locked, offline, enrollment-required, empty, conflict, and failure states. Replace
“Trusted Macs” and “this Mac” with device-neutral wording across shared workflows.
Never infer a security decision from a device's display name or icon.

## Shared architecture and required refactoring

| Existing area | Planned change |
| --- | --- |
| `Package.swift` | Add mobile platform support and library products for app support/shared UI. Ensure mobile targets do not build CLI executables or desktop-only helpers. Verify the pinned zxcvbn dependency and dictionary resources in an installed mobile bundle. |
| `MopAppSupport/VaultService.swift` | Keep typed operations, serialization, revision checks, and cancellation generations shared. Inject state location and platform identity configuration instead of mobile use of `~/.mop` or environment overrides. |
| `MopAppSupport/CLIClient.swift` | Move the subprocess adapter to a macOS-only target or conditionally compile it out of mobile builds. Mobile uses `NativeVaultService` directly. |
| `MopApp/AppModel.swift` | Extract shared observable state and workflows into a library. Inject clipboard, lifecycle/activity, and file-presentation services; remove direct AppKit dependencies from shared state. Preserve separate operation and visibility generations. |
| `MopApp` views | Move the root split view, item lists/cards, drafts, generator, strength, recently-deleted, settings, and management forms into one shared UI library. Thin build entry points and conditional scene modifiers must host the same root view. |
| `MopKeychain/SigningIdentity.swift` | Split macOS code-signature inspection from mobile configuration and entitlement enforcement. Current `SecCode` checks, hardened-runtime checks, and `Contents/embedded.provisionprofile` assumptions are desktop-specific. |
| `MopAuth`, `MopVault/LocalDevice.swift` | Verify Face ID/Touch ID, device-passcode fallback, strict biometrics, and existing Secure Enclave ACL behavior. Generalize device labels without changing serialized identities. |
| `MopCore/PrivateACL.swift`, `MopVault/SafeFile.swift`, cloud cache | Separate desktop ACL handling from mobile sandbox/Data Protection and document-provider handling. Audit Darwin calls and filesystem assumptions across the dependency graph. |

Prefer small platform adapters to duplicated UI or business logic. Every platform
branch needs an API-availability, lifecycle, or demonstrated interaction reason;
device type alone is not a reason to fork a screen. Shared model tests
should import the new library instead of depending on an application executable.
No schema migration should be necessary; prove this with cross-platform fixtures
and actual mixed-device operation before committing to release.

## Security and platform behavior

### Signing, storage, and cloud identity

Provision the mobile bundle under the existing developer team and explicitly
associate it with the existing CloudKit container. Stop deriving the container
name from the mobile bundle identifier: the current implementation does so and
would select a different container if the new bundle identifier differs. Apple
supports multiple apps sharing a container; validate the Development and Production
environments independently. See [Enabling CloudKit](https://developer.apple.com/documentation/cloudkit/enabling-cloudkit-in-your-app).

Use supported iOS entitlement enforcement and a provisioned Keychain access group;
retain a Keychain probe that fails closed for an inaccessible group. Do not replace
desktop signature validation with a blanket success result or rely on a bundled
configuration string as proof of entitlement. The exact mobile validation mechanism
is an early prototype deliverable, tested with distribution signing as well as
development signing. Keep any test identity injection out of production paths.

Store state in app-private Application Support with explicit Data Protection,
device-bound non-synchronizing Keychain material, account scoping, and a documented
backup-exclusion policy for device identity and caches. Preserve atomic writes,
bounded reads, protected destinations, and no-overwrite behavior inside the app
container. Confirm availability of POSIX/ACL functions by compiling against the
mobile SDK; do not simply suppress permission failures. Apple's
[file protection API](https://developer.apple.com/documentation/foundation/fileprotectiontype)
provides the mobile at-rest protection mechanism.

Test reinstall, backup restoration, and device replacement: cached metadata or
surviving Keychain records must not silently enroll a device or bypass trust.
Unavailable device keys lead to explicit recovery or enrollment.

### Authentication and lifecycle

Add the Face ID usage description and appropriate biometric/passcode wording.
Keep `.biometryCurrentSet` for strict mode and `.userPresence` for ordinary mode;
prove behavior on real hardware, including biometric enrollment changes. Keep
authentication off the main thread and invalidate pending contexts on lock.

Proposed mobile lifecycle policy:

1. On inactivity, immediately cover the entire sensitive UI, conceal revealed
   values, dismiss generation previews, and invalidate pending reveals/copies.
   A temporary inactive transition caused by an authentication prompt must not
   cancel its own authentication session.
2. On background entry, end authorization and discard catalogs/drafts. On return,
   require authentication. This deliberately adapts the Mac's background session
   retention to mobile suspension; explain it in Settings.
3. Preserve an intentionally copied concealed value through ordinary app switching
   until its original 30-second expiry so copy/paste remains useful. Use a distinct
   background-lock path. Manual lock, observed device locking/protected-data loss,
   account changes, and timeout clear Mop's owned concealed entry when executable.
4. Enforce deadlines on foreground entry; never depend on a suspended timer or
   termination callback for security. Do not save plaintext drafts for restoration.
5. Count user touch, keyboard, pointer, and accessibility interaction toward
   inactivity. Network work must not extend the session.

System file pickers and authentication prompts need explicit lifecycle tests so
the privacy cover does not break their completion flow. Submitted cloud writes
may finish after cancellation: retain the existing reconciliation semantics and
never show stale completion in a different context. Apple requires removing
sensitive content before the system captures the background UI; see
[Preparing your UI to run in the background](https://developer.apple.com/documentation/uikit/preparing-your-ui-to-run-in-the-background).

### Clipboard

Implement the mobile adapter with `UIPasteboard`, `localOnly: true`, and a system
expiration date for concealed values. Track ownership/change count before clearing
to avoid removing another app's newer content. Visible values and references retain
the Mac's non-expiring behavior. Use system expiry as well as an in-process timer
because iOS may suspend Mop. Verify replacement of a concealed copy with a visible
copy cancels old ownership. See Apple's
[pasteboard write options](https://developer.apple.com/documentation/uikit/uipasteboard/setitemproviders(_:localonly:expirationdate:)).

### Recovery files and backups

First replace direct open/save-panel calls with shared SwiftUI file importer/exporter
presentation, providing native dialogs on Mac and Files flows on mobile. Retain a
small platform file adapter only where required to preserve security guarantees;
do not duplicate the surrounding recovery/export UI. Use security-scoped access.
Keep document-provider I/O at a dedicated boundary: imported recovery material is
bounded and copied into protected private staging before existing parsing. Do not
assume a Files provider exposes Mac POSIX permissions, hard links, or ACL semantics.
See [UIDocumentPickerViewController](https://developer.apple.com/documentation/uikit/uidocumentpickerviewcontroller).

Vault creation needs a resumable state machine: allocate UUID and recovery material,
stage privately, export recovery credential successfully, then publish the vault.
Cancellation before export completion must not publish; uncertain publication
retains the original UUID and key for reconciliation. A process restart must offer
resume/reconciliation rather than generating a different recovery credential.

Export backups from an authenticated online or verified offline snapshot. Use
unique filenames and report provider cancellation/failure without reporting success.
Prototype collision handling: Files providers may not offer the same atomic
no-overwrite guarantee as local `SafeFile`. Select a supported destination flow
that preserves it, or document the precise limitation before release. Keep recovery
credentials and backups separate. Remove staging material after confirmed completion;
retain only the protected material needed for interrupted creation recovery.

## Delivery sequence and exit criteria

1. **Portability and hardware prototype.** Add a multiplatform app target hosting
   the shared root view and
   compile shared dependencies for simulator and device. Resolve platform-only APIs,
   test estimator resources, provision CloudKit, prove Secure Enclave create/open,
   authenticate, enroll with a Mac, read one secret, and export a recovery file.
   Exit: a signed phone and tablet work with the same test vault; signing and Files
   limitations are resolved or explicitly recorded. No production vault experiment.
2. **Shared app foundation.** Extract the single root/interface and model into a
   shared UI library with narrow platform adapters; migrate the Mac to this same UI;
   inject storage/configuration. Run existing Mac tests and signed Mac smoke checks.
   Exit: all three platforms render the same view types, desktop behavior stays
   intact, and shared workflows run in mobile tests. Validate compact split-view
   navigation and common file dialogs before introducing any native UI exception.
3. **Complete daily workflows.** Implement adaptive navigation, discovery/unlock,
   search, item/field editing, all templates, generator/strength, secret actions,
   Recently Deleted, offline viewing, settings, and lifecycle protection.
   Exit: every corresponding parity row passes on both form factors.
4. **Complete administration.** Add resumable creation, enrollment, approval,
   trust, recovery, revocation, rename, deletion, and backup export. Generalize
   device terminology in the Mac UI too. Exit: Mac↔iPhone↔iPad interoperability
   works in both directions, including key rotation and concurrent edits.
5. **Release validation.** Finish accessibility/layout tests, distribution-signed
   testing, build automation, icons, privacy/configuration review, documentation,
   and TestFlight validation. Exit: all parity and security acceptance checks pass;
   no simulator-only evidence substitutes for hardware acceptance.

These are dependency-ordered milestones, not separate reduced-feature releases.
Estimate the remaining implementation effort after milestone 1 resolves the
signing, SDK, and document-provider uncertainties.

## Verification and release gates

- Run existing core, cloud, vault, and app-support tests on macOS; run portable
  suites and shared-model tests on the iOS simulator. Retain CLI regression tests.
- Add focused adapter/model tests for late authentication/read/write results,
  foreground deadlines, inactive authentication prompts, clipboard ownership and
  expiry, background draft clearing, protected-data loss, account changes, and
  interrupted recovery export/publication.
- UI-test the parity table on a small iPhone, a large iPhone, and iPad in wide/narrow
  layouts, with rotation, software/hardware keyboards, and accessibility sizes.
- Exercise the same shared screens on Mac. Review platform conditionals and record
  why each is needed; reject duplicated platform screens where SwiftUI can adapt.
- On physical devices, verify Face ID, Touch ID where supported, fallback and strict
  policies, device lock, suspension/termination, clipboard expiry while suspended,
  task-switcher snapshots, offline reopening, and Files cancellation/collisions.
- Use a Mac, iPhone, and iPad on the same test iCloud account for enrollment from
  each platform, approval from another, recovery, revocation/key rotation, conflict
  rejection, offline snapshot trust, Recently Deleted retention, and vault deletion.
- Distinguish immediate online revocation enforcement from already acquired offline
  snapshots: do not claim removal can erase another device's cached data or backups.
- Test cloud failure after submission and force termination during creation/export.
  Restart must reconcile existing state without duplication or lost recovery keys.
- Add reproducible Xcode build/test/archive instructions and CI simulator checks.
  Test signed builds against the intended CloudKit environment, verify distribution
  entitlements/resources, and complete hardware acceptance before release.

## Decisions to record during implementation

Proceed with the defaults above; none requires blocking this planning task.
Before the release configuration is finalized, record the mobile bundle identifier,
supported OS minimum, signing/provisioning ownership, distribution channel, and
approved document-provider guarantees. Treat AutoFill and multiple Mop windows as
separately scoped additions, not implicit requirements for the parity release.
