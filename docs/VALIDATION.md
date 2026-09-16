# Testing and validation

This page records test coverage, hardware results, and checks that still need
manual validation. For installation and usage, see the [README](../README.md).

## Security regression update: 2026-09-16

Validated after the fixes: all 39 Swift tests, 69 CLI smoke checks against the
ad-hoc-signed release build, and the standalone security audit probe passed.
The probe confirms that both Unicode encodings are masked, recovery ACLs are
stripped, and forged vaults and old-key replays are rejected.

The security fixes add local vault-key pins, strip inherited ACLs before private
file writes, reject ACL allow entries on private reads/directories, and retain
byte-distinct Unicode masking patterns. The regression suite covers complete
attacker-encrypted vault replacement, forged history, missing pins, changed vault
identities, second-device trust bootstrap, rotation requiring new evidence,
recovery bootstrap, old-key replay rejection on a Mac with an updated pin, and
history restoration retaining the current key. It uses disposable software keys.

Hardware and live two-Mac workflows below predate the security update and must be
repeated with the new trust commands. Enrollment now also requires verification of
the vault fingerprint on the new Mac; rotation requires updating the remaining
Macs' pins. Recovery on a fresh Mac requires an independently saved fingerprint or
a known-good backup revision hash. Replaying an older revision under the same
still-trusted key remains outside this fix.

## Secure Enclave hardware results: 2026-09-16

macOS 27.0 (26A428), Apple Silicon, Xcode beta / Swift 6.4:

- CryptoKit reported Secure Enclave availability and LocalAuthentication reported
  device-owner authentication availability in a logged-in terminal.
- An ad-hoc-signed command-line executable generated a user-presence-protected
  P-256 key and saved its opaque representation in a temporary file.
- A new process reopened that representation and decrypted a disposable HPKE
  payload after macOS authentication.
- A separate new process with authentication UI disabled was denied with
  `com.apple.LocalAuthentication` / `notInteractive` (-1004).
- The real `mop vault init` and `mop write` commands created and updated a disposable
  encrypted file using a separate local device record and recovery file.
- A subsequent `mop run` command resolved two environment variables referencing
  the same multiline secret and launched a child that verified both values after
  fresh authentication, without printing the secret.

These checks cover local hardware access. Cross-device iCloud synchronization
and an independent cryptographic audit are outside their scope.

## Manpage and shell support

The release package includes `share/man/man1/mop.1` and generated Bash, zsh, and
Fish completions. Validation covers generation without a vault, equality with the
built-in generator, Bash/zsh syntax, actual macOS Bash candidates (including paths
with spaces), zsh autoload registration, and manpage rendering. Installer tests
verify all four resources on fresh installs and upgrades, and refuse unrelated
files or symlinks. Fish was not installed on the validation host: generation and
packaged content were checked, but Fish runtime checks remain unverified. The test
script automatically performs Fish syntax/candidate checks when Fish is available.

```sh
python3 scripts/test-shell-support.py dist/mop
python3 scripts/test-tooling.py dist/mop
```

## Automated checks

Completed successfully for 0.3.0 on 2026-09-16: 33 Swift test functions (including
parameterized cases), the release build with ad hoc signing, 62 CLI smoke checks
against the release executable, installer creation/upgrade/collision checks, and
shell syntax checks. The feasibility observations above are from 0.2.0.

The 0.3.0 release hardware workflow passed on 2026-09-16. Seven separate
CLI commands authenticated successfully: initialization, two field writes, masked
execution, template injection, file read output, and a missing-field failure check.
The run command verified two distinct secrets and a repeated reference, with both
stdout and stderr masked. Sectioned multiline values, environment-variable
expansion, default 0600 output permissions, and unchanged output on a missing-secret
failure all passed. The workflow uses disposable vaults and removes its fixtures after each run.

```sh
swift test
scripts/package.sh
python3 scripts/smoke-test.py dist/mop
python3 scripts/test-tooling.py dist/mop
bash -n scripts/package.sh scripts/install.sh
```

Tests use temporary files and software fixture keys **only in the test target**.
The production CLI has no software-key or no-authentication switch. Tests cover
reference parsing, literal dotenv behavior, secret resolution, file CRUD,
metadata/ciphertext tampering, device enrollment, fingerprint checking, key
rotation, recovery, stale writes, history restoration, and unsafe local files.
CLI smoke checks test parsing, errors without output, environment precedence,
process exit/signal behavior, no implicit shell, and hidden terminal input.
Installer checks use temporary prefixes and verify collision protection.

The 0.3.0 checks additionally exercise sectioned references and expansion,
byte-exact streaming masking (chunk boundaries, overlapping patterns, Unicode,
multiline and binary output), concurrent stdout/stderr traffic, broken-pipe cleanup,
termination forwarding, terminal opt-out, atomic file creation/replacement and
permissions, protected paths/symlinks, failed resolution without output changes,
file enrollment isolation, and v1/v2 migration with recovery/history continuity.

Run the opt-in end-to-end hardware workflow from a logged-in terminal:

```sh
python3 scripts/test-hardware.py dist/mop
```

It requires seven separate authentication approvals and creates only temporary
vaults, local key records, recovery material, and output files. It checks repeated
references and multiple fields under one command's authentication, sectioned
multiline data, masking, expansion, and atomic output. All fixtures are removed on
completion or failure. The script cannot determine which authentication method
was used or count visible prompts; observe those separately.

Run hardware checks from a logged-in terminal. Restricted execution sandboxes
can block Secure Enclave access, LocalAuthentication, NSFileCoordinator, or
pseudo-terminals and produce service or I/O errors.

## Homebrew packaging

The 0.3.0 source snapshot passed a Homebrew source installation on Apple Silicon
with Swift 6.4 on 2026-09-16. Checks included formula style, strict online tap
audit, linkage, formula tests, 78 CLI smoke checks, manpage rendering, and Bash/zsh
completions. Three release-preparation tests also passed. Fish completion contents
were checked; Fish runtime checks were skipped because Fish was unavailable.
Hosted CI and interactive hardware upgrade checks were not covered by this run.

See [Releasing mop](RELEASING.md) for the packaging test commands.

## Reproduce the hardware probe

```sh
scripts/package.sh --check
# Use a fresh path; the fixture contains only an opaque key blob and ciphertext.
dist/mop-enclave-check create /tmp/mop-new-probe.json
dist/mop-enclave-check deny /tmp/mop-new-probe.json
dist/mop-enclave-check open /tmp/mop-new-probe.json
rm /tmp/mop-new-probe.json
```

Creation and opening require separate authentication. Denial must pass without
presenting UI. Repeat after rebuilding the executable to verify key continuity.
Removing the fixture discards the only saved representation of that disposable key.

## Remaining manual acceptance checks

1. Repeat using password fallback, without enrolled Touch ID, and while the user
   session is locked. Cancellation must produce code 3 without secret output,
   modification, or child execution. Observe one authentication per command.
2. On two Macs signed into iCloud Drive, initialize once and enroll the other via a
   public request whose fingerprint is compared on the original device's screen.
   Wait for file sync, verify the vault fingerprint on the second Mac using
   `mop vault trust --fingerprint ...`, and confirm independent Touch ID access.
   Upgrade both binaries before adding sections to a v1 vault; verify the resulting
   v2 file and preserved v1 history arrive intact on both Macs.
3. Disconnect both Macs, modify the same field, and reconnect. Check reported file
   versions, preserved history, stale-write failures, and explicit conflict
   resolution. Confirm the selected contents survive on both Macs. Do not assume
   all provider races are covered by local NSFileCoordinator tests.
4. Revoke the second Mac. After the new file syncs, it must fail to open the new
   revision; remaining Macs must verify the new vault fingerprint before opening it; its old local copies remain readable. Confirm conflict resolution
   preserves the current authorization list instead of restoring revoked devices.
5. Recover onto a replacement device using the offline recovery file and a fresh
   local state directory and an independently verified vault fingerprint. Verify the new device can read after the recovery file
   is removed from that Mac. Never delete the sole remaining recovery copy.
6. Verify metadata and ciphertext tampering are rejected, missing/corrupt device
   records never trigger automatic replacement, and an unusable hardware-bound key
   fails closed. The recovery key is intentionally a separate decryption path.
7. Confirm the selected cloud provider syncs both the vault and its history;
   local device records and recovery credentials must remain outside the shared
   location. Consider backups independently of synchronization.
