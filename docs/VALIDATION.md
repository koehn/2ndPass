# Testing and validation

## CloudKit development design

Version 0.5 requires fresh v4 named vaults; legacy formats have no migration. Unit tests use software keys only in test targets;
production has no software-key or unsigned-build fallback.

The new CloudKit suite uses an injectable in-memory server with conditional saves,
lost responses, missing zones, quota/throttle failures, and account changes. It
covers immutable record reuse, authenticated reconstruction, interrupted commits,
offline caches, rollback/tampering, enrollment, revocation, recovery, and restoration.
Existing cryptographic, parsing, masking, process, output-file, and ACL tests remain.

```sh
swift test
python3 scripts/test-signing-config.py
swift build
python3 scripts/smoke-test.py /path/from/swift-build-show-bin-path/mop
bash -n scripts/package.sh scripts/install.sh
```

Restricted sandboxes can block compiler plugins and pseudo-terminal tests and
inject Python temporary-directory warnings into captured output. Run the full
suite in a normal local development environment. Module caches may need a
writable path in restricted environments.

Local validation on 2026-09-22: successful build, 59 Swift tests, 88 unsigned CLI smoke checks,
signing-profile generation/rejection tests, temporary packaged Bash/zsh completion
and manpage checks, and Homebrew tooling tests. Fish runtime is unavailable;
its generated script was compared but not executed. No real vaults were used.

**No live CloudKit, signed two-Mac, or production acceptance is claimed.** Follow
[CloudKit provisioning and acceptance](CLOUDKIT.md), record results, and promote
the schema only after development validation. No release should be published until
the production smoke test passes.

Security remediation validation on 2026-09-23: all 81 Swift tests and 88 unsigned
CLI smoke checks passed, including
new tests for background completion/authentication focus return, device-local
clipboard helper expiration and ownership (using unique test pasteboards),
rejected cloud downloads, bounded snapshot reuse, and legacy blob cleanup that
preserves offline snapshots and uncertain-commit journals. Signing configuration,
the three release-tooling tests, and shell syntax checks passed. The standalone
cloud audit probe now confirms zero retained blobs after failed syncs.
These checks do not exercise Universal Clipboard across real devices or native
Touch ID focus transitions; include those in GUI acceptance before release.

## Signed packaging and hardware checks

Configure `MOP_SIGN_IDENTITY`, `MOP_PROVISION_PROFILE`, and optionally
`MOP_BUNDLE_ID` as described in the README. Use an explicit profile and keep the
same application ID across upgrades. Packaging and installation run
`mop device identity` to verify code-signing policy and OS Keychain entitlement
without authenticating or creating keys.

```sh
scripts/package.sh
dist/Mop.app/Contents/MacOS/mop device identity
python3 scripts/test-shell-support.py dist/Mop.app/Contents/MacOS/mop
python3 scripts/test-tooling.py dist/Mop.app
MOP_LIVE_CLOUD_TEST=1 python3 scripts/test-hardware.py dist/Mop.app/Contents/MacOS/mop
```

The hardware workflow requires explicit opt-in, creates a disposable cloud vault,
and retains its local state and recovery files until you delete the test zone.
Use a Development build and record the printed fixture directory and vault UUID. It leaves a disposable Keychain item
(service `mop.device-key.v2`) because deleting metadata does not delete Keychain
state. Clean up that test item in Keychain Access if desired; never remove a live
device's item. Run once with default authentication and again with
`MOP_TEST_STRICT_BIOMETRICS=1` to exercise strict mode.

## Application-bound enclave probe

Build `scripts/package.sh --check` using a **separate** explicit profile and
bundle ID (default `net.koehn.mop.enclave-check`). This executable uses the same
LocalDevice implementation as mop.

```sh
probe=dist/MopEnclaveCheck.app/Contents/MacOS/mop-enclave-check
"$probe" create /tmp/mop-new-probe
"$probe" deny /tmp/mop-new-probe
"$probe" open /tmp/mop-new-probe
"$probe" create-strict /tmp/mop-strict-probe
"$probe" open /tmp/mop-strict-probe
```

`deny` must report an authentication error without prompting. Repeat `open`
after rebuilding/reinstalling with the same identity to verify continuity.
`device.json` must contain only public metadata and a Keychain account UUID,
never a blob. Removing the fixture directory does not remove its Keychain item.

For cross-application denial, create a disposable device using the signed mop
app. Run the differently provisioned probe against that metadata and mop's group:

```sh
"$probe" foreign /path/to/disposable/mop-state TEAMID.net.koehn.mop
```

The probe explicitly requests the other app's group and requires
`errSecMissingEntitlement`; missing files, missing items, or authentication denial
do not count as a successful cross-application test. Also run the differently
signed application's normal open against copied metadata; it must not retrieve
the original key. An unsigned/ad-hoc executable's `device identity` and
`device request` must fail with code 8 before authentication or key creation.

## Remaining manual acceptance

- Default policy: Touch ID, login-password fallback, cancellation, locked session,
  no enrolled Touch ID. Observe a fresh authentication on each secret command.
- Strict policy: no password fallback; biometric lockout/unavailability fails
  closed. Changing enrolled fingerprints invalidates access. Omitting the flag
  on later commands preserves strict policy; requesting it on an existing default
  key fails. Tampering with metadata cannot weaken the actual key/item ACL.
  Enrollment changes affect other apps too: use a dedicated test Mac/user for
  that destructive biometric-state test.
- Signed installation: app survives copying/upgrading as a complete bundle;
  copied standalone executable and differently provisioned app cannot retrieve
  its item. Missing Keychain items never cause implicit key replacement.
- Multi-Mac enrollment, independent local trust, CloudKit conflicts, revocation,
  and recovery with an offline credential. Revocation requires repinning the new
  index-key fingerprint on remaining Macs. Historical ciphertext stays readable
  to former recipients. Restoring history must not reinstate their access.

Per-record encryption is not an enclave-enforced allowlist: compromised
already-authorized mop code could unwrap other records. Keys and requested
plaintext still enter ordinary memory. An independent cryptographic and OS
integration audit remains outstanding.

## Named-vault release acceptance

Use two signed Macs and disposable vaults. Create `personal` on A; discover its
name without unlocking on B, enroll B using independently compared fingerprints,
and verify `mop://personal/mycloud/sshd` resolves on both. Add multiple fields
including a section and confirm a single GUI item row. Create another named vault
and verify cross-vault `run`/`inject` and all-vault listing.

Rename `personal` on A. Verify the UUID, fingerprint, recovery access, and values
are unchanged; online B must reject the old name and discover the new name.
Before syncing B, explicitly test its verified offline snapshot with the old name.
Exercise duplicate names from concurrent clients, repair by UUID, and verify
legacy vaults remain unchanged. Export/import a v4 backup into an absent head,
and restore pre-rename history while retaining the current name.

These are manual release gates; passing software-key unit tests does not establish
signed CloudKit, Secure Enclave, or two-Mac acceptance.

## Vault deletion acceptance

On disposable signed vaults, exercise CLI typed confirmation, cancellation,
`--yes` with authentication cancellation, and GUI typed confirmation. Export from
the GUI before deleting; confirm the backup is readable with its recovery key.
Delete a named vault and a legacy vault by UUID, and confirm only those CloudKit
zones disappear. Verify the current Mac's scoped cache/default are removed while
other vaults and shared device keys still work. A second Mac's offline cache must
remain until separately removed. Test a lost delete response and retry the same
UUID; no successful deletion should be reported without verified remote absence.
