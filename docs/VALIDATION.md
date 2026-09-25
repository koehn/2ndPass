# Testing and validation

The supported format is `mop-vault-v5`. Production uses synchronized account keys
and local authentication. Tests use injected account-key storage and cloud
transports; they do not establish real Keychain delivery or biometric enforcement.
Older vaults/backups, device credentials, pairing/enrollment, conversion, and
pre-v5 history restoration are unsupported.

## Automated checks

```sh
swift test --disable-automatic-resolution
swift build --disable-automatic-resolution
python3 scripts/smoke-test.py "$(swift build --show-bin-path)/mop"
python3 scripts/test-signing-config.py
python3 scripts/test-homebrew-release.py
python3 scripts/test-install-layout.py
bash -n scripts/package.sh scripts/install.sh scripts/mobile.sh
scripts/mobile.sh build
scripts/mobile.sh test
```

Swift tests cover encryption/signatures, account membership, trust, recovery,
conditional publication, lost responses, offline caches, rollback, account changes,
item edits, OTPs, output files, processes, and session cancellation.
Regression tests reject v1–v4 documents and stop history at the v4 boundary without
fetching old secret records. Layout tests stub signing; they are not entitlement
tests. Simulator UI tests use explicit Debug-only fixtures. Run supported iPhone
and iPad destinations and record simulator/runtime versions.

Restricted sandboxes may block compiler caches, Security services, or PTYs. A
sandbox failure is not a product result; rerun with the required local permissions.
Historical audit/test reports describe earlier snapshots. Record current build,
platform, command, result, and any skipped check when preparing a release.

### V5-only change validation (2026-09-24)

The working-tree change based on `ccca4d8` passed 234 Mac Swift tests and 99 CLI
smoke checks. Signing configuration, Homebrew release/layout checks, shell syntax,
generated completions, and manpage rendering passed. Fish was unavailable, so its
generated completion was checked without a runtime test.

iOS simulator test builds and the unsigned iOS Release build passed. On iOS 27.0,
iPhone 18 Pro and iPad Pro 13-inch (M5) each passed 204 shared tests and
`testLegacyPairingIsAbsent`. The full iPhone UI suite did not pass: detail-field,
OTP-display, and settings/interruption tests failed. All four failing test cases
also failed when run against an isolated checkout of `ccca4d8`. These failures
were resolved in the follow-up below. The full iPad UI suite was not run at that
earlier snapshot.

These checks used fixtures. Signed physical-device authentication, actual iCloud
Keychain delivery, and live Development/Production CloudKit acceptance were not
performed as part of this change.

### UI-test follow-up (2026-09-24, based on `a67ecfd`)

The four original failures queried copy controls as static text. Tests now locate
the username button and identify OTP elements independently of their accessibility
element type, while retaining code-format, layout, replacement-validation, and
interruption assertions. The lock assertion also checks the actual copy control.

Full iPad testing exposed additional automation assumptions: sidebar overlays
consume taps meant for underlying content, the vault section can remain collapsed,
and batched simulator keyboard input can omit characters. Tests explicitly handle
the sidebar, synchronize title/OTP key events, and check the complete item name
before and after both rotations. No production app code changed.

On iOS 27.0, iPad Pro 13-inch (M5) passed all 201 shared tests and 14 UI tests;
the final OTP-entry helper also passed a focused iPad rerun. iPhone 18 Pro passed
all 201 shared tests and 13 UI tests in the final full run. Its rotation test was
interrupted by a `testmanagerd` crash and passed in an isolated rerun. Thus every
UI case has passing evidence on both platforms, but the final iPhone full-run
result itself is failed due to the test-runner crash. A separate attempt also
failed to launch after the simulator service exited; it supplied no product result.

The installed `/Applications/Mop.app` passed deep, strict code-signature verification
with an Apple Development identity, the expected Mop Keychain access group, and
Development CloudKit entitlements. This verifies a signed Mac installation, not
completion of hardware acceptance or Production distribution testing. Installed
iPhone/iPad artifacts were not inspected during this follow-up.

## Signed Mac packaging checks

Configure the explicit profile and signing identity as in README. Keep the bundle
ID, access group, container, and environment stable across updates.

```sh
scripts/package.sh
dist/Mop.app/Contents/MacOS/mop device identity
python3 scripts/test-tooling.py dist/Mop.app
python3 scripts/test-shell-support.py dist/Mop.app/Contents/MacOS/mop
MOP_LIVE_CLOUD_TEST=1 python3 scripts/test-hardware.py dist/Mop.app/Contents/MacOS/mop
```

The live script creates a disposable **v5 vault** on the signed build's account.
Use a dedicated test Apple Account and Development environment. It may initialize
or reuse that account's synchronized Mop identity. An isolated state directory
does not create an isolated Keychain identity. Retain the printed vault UUID and
recovery file until deliberate cleanup. Delete only the test vault and its local
fixtures; never delete the shared synchronized identity as cleanup.

Run the script with ordinary system authentication. No device enrollment or
separate enclave probe is used.

## Required physical acceptance

Use signed Mac, iPhone, and iPad builds with matching provisioned Keychain access
groups and CloudKit environments, on a dedicated test account.

Installing and running Mop through Xcode on a physical iPhone or iPad counts as
testing a signed, provisioned build. A Mac bundle signed with an Apple Development
identity also counts. Development signing is sufficient for the hardware checks
below; distribution signing is a separate release check. This project's Xcode
Debug configuration targets Development CloudKit, while Release targets Production.
Verify the installed artifact's entitlements when recording results. Installing
successfully establishes deployment; record which authentication, synchronization,
recovery, and failure scenarios you actually exercised. Everyday use provides
evidence for those paths, not automatic completion of the entire matrix.

1. Create a fresh v5 vault on A, write multiple typed fields and an OTP, export a
   backup, and independently retain its fingerprint. Wait for iCloud Keychain
   delivery on B/C. Open all owned vaults without QR pairing or enrollment.
2. Exercise delayed/missing identity delivery, disable/re-enable Keychain sync,
   lock/relaunch, and install an update over existing apps. Missing keys must
   produce a waiting error without replacing the public anchor or private keys.
3. Test default Face ID/Touch ID/password or passcode fallback, cancellation,
   lockout, unavailable biometrics, and lock during a pending prompt. Authentication
   uses the system device-owner policy; no biometric-only mode is offered.
4. Verify interface/app-switcher concealment, inactivity expiry, protected-data
   loss, clipboard expiration during suspension, and no late visible result after
   lock. Verify shared sessions across owned vaults and fast reads during refresh.
5. Check concurrent writes, conflicts, interrupted staging, lost head responses,
   uncertain recovery publication, quota/throttling, and explicit reconciliation.
   Follow [CloudKit acceptance](CLOUDKIT.md) for the publication sequence.
6. Verify CLI explicit offline access and native automatic connectivity fallback;
   no offline writes and no fallback for identity/trust/account failures. Test
   sign-out, another Apple Account, and Development/Production isolation.
7. Restore a supported v5 historical revision under current authorization. On a
   vault previously converted by an older release, verify listing stops at the
   v4 boundary and requesting an old revision fails without changing the head.
   Reject v4 imports/opens even if old device metadata and keys are present.
8. Recover a v5 backup into another test account with a usable identity, using its
   recovery credential and independent evidence. Verify all values and metadata,
   new owner/key wraps, source-file preservation, and exclusion of account keys
   from exports. Do not reset an existing missing account identity implicitly.
9. Test file providers, import/export cancellation, collisions, interrupted mobile
   setup, pending-creation reconciliation, and deletion of supported/unsupported
   vaults by explicit selection. Do not resurrect absent heads automatically.
10. Check small/large phone and iPad layouts, orientation, keyboard/pointer,
    Dynamic Type, VoiceOver, Reduce Motion, and minimum supported OS versions.
11. Verify unsigned/tampered signing rejection and cross-application Keychain
    access-group denial using disposable accounts/fixtures. A missing fixture is
    not proof of denial. Observe identity continuity after a signed upgrade.

## Release gate

Complete Development acceptance, deploy the schema, then run a disposable
initialize/write/read/export/recovery smoke test with distribution-signed
Production builds. Record evidence for actual Keychain synchronization and
biometrics. No simulator or mocked suite substitutes for those checks. Do not
publish until the Production smoke test and required physical acceptance pass.
