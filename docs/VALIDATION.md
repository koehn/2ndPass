# Testing and validation

The supported format is `mop-vault-v6`. Read the current [validation record](VAULT-NEXT-VALIDATION.md)
for concrete results, retained test resources and unperformed physical checks.
Recovery is optional; configuring hardware recovery uses a separate recovery device. No v5 migration or
software-key fallback is supported; existing user data must be preserved.

## Automated checks

```sh
swift test --disable-automatic-resolution
swift build --disable-automatic-resolution
python3 scripts/smoke-test.py "$(swift build --show-bin-path)/mop"
python3 scripts/test-signing-config.py
python3 scripts/test-homebrew-release.py
python3 scripts/test-install-layout.py
bash -n scripts/package.sh scripts/install.sh scripts/mobile.sh
xcodebuild -project Apple/Mop.xcodeproj -scheme Mop \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath .build/v6-apple -clonedSourcePackagesDirPath .build \
  CODE_SIGNING_ALLOWED=NO -disableAutomaticPackageResolution build-for-testing
```

Tests cover automatic same-account iCloud enrollment without confirmation, locked-owner refusal,
signed revisions, invitation replay and substitution, owner/editor/viewer
authority, device/member removal, recovery, typed catalog edits, stale AutoFill
locators, concurrent writes, interrupted publication, journal recreation, account
changes and cancellation. Test software keys and injected transports are confined
to tests; they establish logic, not Secure Enclave or CloudKit permissions.
Layout checks stub signing. Build-for-testing compiles tests but does not run them.

Restricted sandboxes can block compiler caches, Security services and PTYs. Record
host checks separately. Historical audit reports describe earlier implementations;
their counts and platform results are not current v6 acceptance.

## Signed packaging and live checks

Use a matching explicit provisioning profile and signing identity as documented
in the README. Build and verify a new bundle before using packaging checks; an
existing `dist` artifact may still be an older client. Do not replace an installed
client or delete user data as part of validation.

```sh
scripts/package.sh
python3 scripts/test-tooling.py dist/Mop.app
python3 scripts/test-shell-support.py dist/Mop.app/Contents/MacOS/mop
MOP_LIVE_CLOUD_TEST=1 python3 scripts/test-hardware.py \
  dist/Mop.app/Contents/MacOS/mop
```

The live script creates a fresh v6 CloudKit vault and retains its local state.
Use dedicated test Apple Accounts and Development CloudKit. To include optional
recovery, pass --recovery-request and --fingerprint together, using a separate
hardware device and independently verified fingerprint. State-directory isolation does not isolate device Keychain identities.
Do not delete an identity as test-vault cleanup. The updated script has not yet
completed a live v6 run.

## Physical and release acceptance

Follow the full matrix in [the validation record](VAULT-NEXT-VALIDATION.md#required-remaining-physical-acceptance).
Use two actual accounts with multiple devices, including signed Mac and iOS builds.
Test invitations, participant identity binding, editor/viewer CloudKit permissions,
removal, shared-database CAS conflicts, hardware recovery and new-account recovery.
Check cancellation, screen lock, protected-data loss, app/CLI/AutoFill routing,
offline reads, account changes, exports and interrupted publication.

Development signing is sufficient for hardware checks. Production distribution
is separate: deploy the v6 schema and run disposable creation, sharing, reading,
editing, export and hardware recovery checks with distribution-signed builds.
Verify entitlements on the installed artifacts. No mocked or simulator test
substitutes for the physical and cross-account acceptance. Do not release until
these gates pass.
