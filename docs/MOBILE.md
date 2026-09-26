# Shared Apple application

**V6 update:** The coordinated hardware/shared-vault cutover is implemented. The current workflow is documented in [the README](../README.md) and [validation status](VAULT-NEXT-VALIDATION.md); remaining physical acceptance is not implied by historical build notes below.

Mop uses the same SwiftUI views and application model on macOS, iPhone, and iPad.
`Sources/MopUI` owns the interface; `MopApp` is a thin entry point. The existing
Mac CLI, packaging, signing checks, and installer remain supported.

Open `Apple/Mop.xcodeproj` and select the Mop scheme. The deployment minimums are
iOS/iPadOS 18 and macOS 15. iPhone and narrow iPad windows use the collapsed
navigation split view; larger windows show columns. Settings, item editors,
password generation, Recently Deleted, account membership, and vault administration
use the same views on every platform. One mobile window is supported.

## Build and test

```sh
swift test
scripts/mobile.sh build
scripts/mobile.sh test
# Optional: select one simulator explicitly.
MOP_SIMULATOR_DESTINATION='platform=iOS Simulator,id=SIMULATOR_UUID' scripts/mobile.sh test
```

The build command compiles the shared tests and UI runner for the simulator, then
compiles a Release build for physical devices without signing. Test chooses one
available iPhone and one iPad. Install a simulator runtime through Xcode Settings
first if none is available. The Apple applications CI workflow runs these commands.

UI automation explicitly sets `MOP_UI_TESTING=1` to use sample data. That fixture is
compiled only in Debug simulator builds. It cannot authenticate, contact a real
vault, or establish hardware security results. Release and device builds always
use the native service. Shared vault tests use injected transports and test keys.

Keep using `scripts/package.sh` for the distributable Mac bundle and its embedded
CLI. The Xcode Mac destination is useful for shared UI development; it does not
replace the CLI packaging workflow.

## Files and interrupted creation

Recovery-key and backup export use a native folder picker followed by an exclusive
write with a unique filename. Existing files are never overwritten. A provider
that cannot support the required safe file operations returns an error; choose a
different writable folder. Mop does not fall back to an overwrite-capable export.
Recovery imports use coordinated, security-scoped access and a bounded private
copy, which is removed when the recovery form closes.

Creating a vault first saves a durable intent with its UUID and recovery key in
private application storage. Export the recovery key, confirm offline custody,
then Continue to authenticate and publish. Reopening Create Vault resumes any
unfinished intent. Names cannot be changed after preparation. You can discard
an unsubmitted setup to start over; submitted attempts must be reconciled.
The initial encrypted snapshot and account binding are persisted before submission.

If a response is lost, Continue reconciles the same snapshot and UUID with cloud
history. If a previously submitted creation has no cloud head, Mop fails closed
instead of recreating a possibly deleted vault. Retain the exported key and use the
existing CLI recovery/import tools or investigate cloud state before removing any
pending intent. Mop does not automatically abandon an uncertain creation.

Private mobile state uses complete Data Protection and is excluded from device
backup. Account access requires an explicitly approved hardware device identity; copying app storage alone does
not transfer the account private keys.

## Mobile sessions

Temporary inactivity immediately covers the entire window, including sheets, and
conceals revealed values. An authentication prompt does not cancel its own session.
Both apps launch locked and automatically authenticate all connected vaults while
active. There is no Unlock button. Vaults open together; any failure clears the
entire session. Unconnected vaults have a distinct add-device icon and are excluded.
Entering the background conceals the interface and discards unsaved drafts, but
preserves authorization until the inactivity deadline. Returning before that
deadline reuses the session. Activity resets the 1–60 minute timeout (default 5);
background work does not. Expiry requires fresh authentication. Cancelling a prompt
pauses automatic retries until another interaction or background/foreground cycle.

Copied concealed values remain available during ordinary app switching for their
original 30-second lifetime. The iOS pasteboard enforces expiration even while Mop
is suspended. Explicit lock clears owned concealed content; newer clipboard
content from another application is preserved. Visible values and references do
not expire. Copies are device-local. Account changes and protected-data loss
invalidate authorization. Submitted writes may still complete and need refresh.

## TestFlight

The project uses team `VE3U9KBEW4`, bundle identifier `com.koehn.mop`, and the existing
`iCloud.com.koehn.mop` container. Debug uses Development CloudKit; Release uses
Production. Keep the mobile App ID associated with that same container. Device private keys never synchronize; approve each device explicitly. Verify matching
provisioned access groups; sharing a CloudKit container alone is insufficient.

Before creating a distribution archive, configure the Apple account in Xcode and
install the appropriate iOS provisioning profiles and Apple Distribution identity.
Verify the existing Production schema and indexes described in `docs/CLOUDKIT.md`.

```sh
MOP_BUILD_NUMBER=1 scripts/mobile.sh archive
MOP_BUILD_NUMBER=1 scripts/mobile.sh export
```

Use a new build number for subsequent TestFlight uploads. Export produces a local
IPA under `dist/mobile`; it does not upload or publish it. Validate and upload using
Xcode Organizer or Transporter after completing acceptance. The Info.plist declares
non-exempt encryption; complete the applicable App Store Connect encryption review
for the vault cryptography before distributing the beta. Supply the beta description,
contact information, privacy policy, and review instructions in App Store Connect.

The mobile icon is derived from the existing Mop artwork at 1024×1024 with an opaque
background. Xcode packages the password estimator's dictionary resources through
SwiftPM.

## Physical-device acceptance

### Validation recorded on September 23, 2026

- All 193 Mac package tests pass, including CLI, vault, shared model, and estimator tests.
- All 171 shared mobile tests and four UI tests pass on iPhone 17e and iPad mini simulators.
- The same four UI tests also pass on iPhone 18 Pro Max and 13-inch iPad Pro simulators,
  covering browsing, editing, password generation, locking, background entry, settings,
  retained drafts during rotation, and accessibility text size.
- The Xcode application builds for macOS and for an unsigned Release iOS device destination.
- Desktop signing configuration, signed installation checks, and installation-layout tests pass.
  The updated Mac bundle and embedded CLI were rebuilt and signed with the existing
  development identity and existing Mac bundle identifier before installation checks.
- Simulator validation uses the downloaded iOS 27.0 runtime with an iOS 18 deployment target;
  execution on the minimum supported OS is still pending.
- The Release device application includes the estimator dictionaries and excludes the UI-test fixture.

The host has Apple Development signing identities but no Apple Distribution identity,
and no physical iPhone or iPad is connected.
No distribution-signed archive, TestFlight upload, or Production CloudKit acceptance
has been completed. Real-device biometrics, passcode policy, device enrollment and hardware key persistence,
suspension, file-provider behavior, and VoiceOver/keyboard acceptance remain required.

Automated tests do not replace these checks with a Mac, iPhone, and iPad on a test
account:

- Face ID, Touch ID on supported hardware, passcode fallback,
  cancellation, changed biometric enrollment, and pending authentication at lock.
- Explicit hardware device enrollment, independent recovery evidence, v6
  backup recovery, ownership-change key rotation, concurrent edits, and account changes.
- Verified offline reads, automatic fallback on disconnection and refresh on reconnection, Recently Deleted,
  and confirmation that remote changes cannot erase previously obtained offline data.
- App-switcher privacy, device lock, protected-data loss, suspension, clipboard
  expiry while suspended, and no late result reopening a locked interface.
- Files providers, collisions, cancelled import/export, termination during creation,
  lost cloud responses, and resume without replacing recovery credentials.
- Small/large phone layouts, narrow/wide iPad windows, keyboard and pointer input,
  Dynamic Type, VoiceOver, Reduce Motion, and portrait/landscape transitions.
- Distribution-signed builds and Production CloudKit. Keep production user vaults
  out of destructive acceptance tests.

The bundled privacy manifest declares app-local preferences, session timers, and
metadata access for private or explicitly selected files, following Apple’s
[required-reason API documentation](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitypereasons).

## Account access

Mop device identities require explicit approval. New devices must enroll before opening
account-owned vaults without QR pairing. See [account identities](ACCOUNT-IDENTITY.md)
for waiting states, recovery, and physical acceptance.

Authenticated item reads use the current verified in-memory snapshot and do not
wait for iCloud. While the app is active, push notifications, foregrounding,
reconnection, and a periodic fallback reconcile changes without disabling item
controls. Verified updates refresh the viewed vault and item; editing defers UI
replacement. A changed revision conceals any revealed value. Lock or expiry clears
snapshot access, and reconciliation detects remote ownership changes.

The Developer setting (which enables Copy Reference) synchronizes using iCloud
key-value storage across the same Apple Account. App signatures must include
`com.apple.developer.ubiquity-kvstore-identifier` with the same team-prefixed
`com.koehn.mop` identifier on macOS and iOS. Regenerate provisioning profiles if
this capability is not yet authorized. Sync delivery is asynchronous; the setting
remains locally usable while offline.
