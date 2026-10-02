# Testing and validation

The supported format is `mop-vault-v7`. Read the current [validation record](V7-VALIDATION-2026-09-27.md)
for concrete results, retained test resources and unperformed physical checks.
Offline recovery is optional. See [SALE-1 validation](OFFLINE-RECOVERY.md). No old-format migration or
software device-key fallback is supported; existing user data must be preserved.

## Automated checks

```sh
swift test --disable-automatic-resolution
swift build --disable-automatic-resolution
python3 scripts/smoke-test.py "$(swift build --show-bin-path)/sp"
python3 scripts/test-signing-config.py
python3 scripts/test-homebrew-release.py
python3 scripts/test-install-layout.py
bash -n scripts/package.sh scripts/install.sh scripts/mobile.sh
xcodebuild -project Apple/Mop.xcodeproj -scheme Mop \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath .build/v7-apple -clonedSourcePackagesDirPath .build \
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
their counts and platform results are not current v7 acceptance.

## Signed packaging and live checks

Use a matching explicit provisioning profile and signing identity as documented
in the README. Build and verify a new bundle before using packaging checks; an
existing `dist` artifact may still be an older client. Do not replace an installed
client or delete user data as part of validation.

```sh
scripts/package.sh
scripts/package-cli.sh
python3 scripts/test-tooling.py "dist/cli/2ndPass CLI.app"
python3 scripts/test-shell-support.py "dist/cli/2ndPass CLI.app/Contents/MacOS/sp"
MOP_LIVE_CLOUD_TEST=1 python3 scripts/test-hardware.py \
  "dist/cli/2ndPass CLI.app/Contents/MacOS/sp"
```

The live script creates a fresh v7 CloudKit vault and retains its local state.
Use dedicated test Apple Accounts and Development CloudKit. State-directory isolation does not isolate device Keychain identities.
Do not delete an identity as test-vault cleanup. The updated script has not yet
completed a live v7 run.

## Physical and release acceptance

Follow the full matrix in [the validation record](VAULT-NEXT-VALIDATION.md#required-remaining-physical-acceptance).
Use two actual accounts with multiple devices, including signed Mac and iOS builds.
Test invitations, participant identity binding, editor/viewer CloudKit permissions,
removal, shared-database CAS conflicts, same-account offline recovery.
Check cancellation, screen lock, protected-data loss, app/CLI/AutoFill routing,
offline reads, account changes, exports and interrupted publication.

Development signing is sufficient for hardware checks. Production distribution
is separate: deploy the v7 schema and run disposable creation, sharing, reading,
editing, export and offline recovery checks with distribution-signed builds.
Verify entitlements on the installed artifacts. No mocked or simulator test
substitutes for the physical and cross-account acceptance. Do not release until
these gates pass. Cross-account sharing is not yet implemented as a supported
feature. Address the [mailbox design detail](SECURITY.md#shared-zone-enrollment-exposure)
when completing sharing, then validate with disposable accounts: a writable share participant must not be able to
induce owner enrollment through the mailbox. Existing per-address model mailboxes
do not establish this server-side isolation. Independent professional security
review remains outstanding; protocol and implementation require separate review.

## SALE-1 verification status — 2026-09-30

The full Swift suite passed 514 tests outside the filesystem sandbox. A later
focused run passed 48 vault-engine tests and five recovery integration tests after
final ancestry-verification and copy-handling refinements. The macOS build passed.
The iOS Simulator build-for-testing passed for the app, AutoFill, and tests before
those final refinements; a final retry was blocked by sandbox access to simulator
services and compiler caches.

CLI smoke execution was not started because automatic approval review exhausted
its usage limit. The changed Python scripts passed syntax parsing. Production
CloudKit schema deployment, signed physical-device recovery with the same Apple
Account, and independent cryptographic review remain pending. No production data
or real Keychain identity was changed by this implementation session.

## Subscription reporting preview

`Tests/MopSubscriptionTests` covers verified-claim policy, expiry/grace/revocation,
account/product/environment rejection, independent renewal freshness, offline
cache expiration, deadlines and late callbacks, purchase outcomes, durable
publication retries, and account switching. Test adapters deliberately use unsigned
fixtures; the real Apple verifier separately rejects those fixtures.

Run `python3 scripts/test-subscription-cli.py PATH_TO_UNSIGNED_SP` against a local
unsigned build to check help/version/completion exemptions, JSON/null date fields,
offline inspection, and stderr-only operational reporting. This test requires no
purchase or vault and expects unsigned configuration to report unavailable.

On 2026-10-01 the full Swift suite passed (454 tests), the CLI and macOS app built
for arm64 and x86_64, and iOS simulator and Release device app/extension builds
succeeded with code signing disabled. These results do not validate live StoreKit
purchase publication or CloudKit consumption. Follow [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)
for product/schema configuration and signed cross-device validation before enabling
production publication or releasing a paid offering.
