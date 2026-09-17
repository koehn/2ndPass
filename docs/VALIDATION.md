# Testing and validation

## Current development design

The v3 record format and application-bound Keychain backend are breaking changes.
Earlier successful ad-hoc Secure Enclave probes do **not** validate this backend.
No signed hardware or two-Mac acceptance result is claimed for this change.

Validated for this change on 2026-09-16: 42 Swift tests, 78 noninteractive CLI
smoke checks, signing-profile generation/rejection checks, unsigned device
creation rejection before writes, packaging refusal without an identity, Bash/zsh
completion checks, and manpage rendering. Completion resources were staged in a
temporary app-shaped directory; this does not validate signed installation.
Fish runtime, signed packaging/installer acceptance, and hardware checks remain
pending; no usable signing identity/profile was available to the test session.

The Swift suite uses disposable software keys only for vault tests. Production
device access has no software, ad-hoc-signing, file-blob, or no-authentication
fallback. Tests cover independent record reads, index-only listing, ciphertext
preservation during unrelated writes, full-table tamper detection, purpose/vault
binding, enrollment rewrapping, all-record revocation rotation, recovery, history
restoration retaining current authorization, local trust, and rejection of legacy
formats. Existing parsing, masking, process, output-file, and ACL tests remain.

```sh
swift test
python3 scripts/test-signing-config.py
swift build
# Substitute the path printed by swift build --show-bin-path:
python3 scripts/smoke-test.py /path/to/debug/mop
bash -n scripts/package.sh scripts/install.sh
```

Restricted sandboxes can block NSFileCoordinator and subprocess/PTY tests. Run
those tests in a normal local development environment. Module-cache paths may
need to be set to a writable directory in restricted environments.

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
python3 scripts/test-hardware.py dist/Mop.app/Contents/MacOS/mop
```

The hardware workflow asks for seven separate authentications and uses temporary
vaults, recovery files, and device metadata. It leaves a disposable Keychain item
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
- Multi-Mac enrollment, independent local trust, iCloud conflicts, revocation,
  and recovery with an offline credential. Revocation requires repinning the new
  index-key fingerprint on remaining Macs. Historical ciphertext stays readable
  to former recipients. Restoring history must not reinstate their access.

Per-record encryption is not an enclave-enforced allowlist: compromised
already-authorized mop code could unwrap other records. Keys and requested
plaintext still enter ordinary memory. An independent cryptographic and OS
integration audit remains outstanding.
