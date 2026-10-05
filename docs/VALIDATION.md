# Validation and release acceptance

2ndPass remains a development preview. Build success, software fixtures and simulator tests are distinct from physical Secure Enclave, live iCloud and release acceptance.

## Recorded physical checks

- October 3, 2026: the user confirmed portable backup/restore, large-vault responsiveness and CLI lookup acceptance, followed by automatic same-account enrollment acceptance.
- October 4, 2026: the user confirmed that an item created on iPhone reached Mac and iPad, a Mac edit reached both other devices, and an offline iPhone edit uploaded after reconnection without manual Refresh.

These observations cover those scenarios only. They do not establish concurrent-edit resolution, cross-account sharing, revocation, recovery after device loss or complete remote backup inventory.

## Automated checks

Run from the repository root with the access described in AGENTS.md:

```sh
CLANG_MODULE_CACHE_PATH=/tmp/mop-clang-cache \
SWIFTPM_MODULECACHE_OVERRIDE=/tmp/mop-swift-cache \
swift test --disable-sandbox

xcodebuild -project Apple/Mop.xcodeproj -scheme MopAutoFill \
  -configuration Debug -destination 'generic/platform=macOS' \
  -derivedDataPath .build/credential-autofill \
  -clonedSourcePackagesDirPath .build CODE_SIGNING_ALLOWED=NO build

scripts/mobile.sh build
scripts/mobile.sh test
```

The full suite needs Unix sockets, process inspection, child processes and test pasteboards. Use elevated execution permissions when the outer sandbox denies them; do not weaken assertions to accommodate environmental failures. Do not start concurrent SwiftPM runners. Apple build/simulator services also require access outside the restricted sandbox.

`sp-keychain-check --run` creates and retains a uniquely scoped disposable hardware identity and checks opaque Keychain reload and signing. It does not validate cloud synchronization or recovery.

## Remaining release gates

- Concurrent same-item edits, explicit conflict resolution, interruption/restart and receipt supersession on physical devices.
- Repeated lock/reopen, relaunch and offline use of a large encrypted catalog; changed and damaged-row repair without data loss.
- Signed app/CLI/AutoFill installation, authentication, account changes, background delivery and protected-store unavailability across supported platforms.
- Independently verified backup completeness, fresh-identity restore and loss-of-account scenarios; device-local exclusions must remain explicit.
- Production CloudKit schema and provisioning validation using disposable vaults.
- Sharing, device removal, recovery, document import and credential-account integration once implemented; physical two-account tests for sharing and permissions.
- Accessibility and every UI flow, purchase/distribution acceptance, and independent cryptographic/security review.

The roadmap tracks these requirements. No automated result substitutes for an unperformed physical or release check.
