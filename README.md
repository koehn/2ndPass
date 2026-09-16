# mop

Source repository: [koehn/2ndPass](https://github.com/koehn/2ndPass).

## Copyright and source access

Copyright © 2026 Koehn Consulting, Inc.
All rights reserved.

The 2ndPass source code is published for inspection and security review.

You may view and analyze the source code.

No license is granted to compile, execute, modify, copy, redistribute, sublicense, sell, or create derivative works from this source code.

For licensing inquiries, contact Koehn Consulting, Inc.

See the [copyright notice](LICENSE). Build, installation, and operational instructions in this repository are for the copyright holder and separately authorized users; they do not grant permission. Third-party dependencies retain their own licenses.

Version 0.3.0.

[Usage examples](docs/EXAMPLES.md) · [Security and key management](docs/SECURITY.md)

A native macOS secrets CLI backed by an encrypted `.mopfile` and a Secure Enclave
key on each authorized Mac. Requires macOS 15+, Secure Enclave hardware, and an
interactive user login session. Build with Xcode / Swift 6+.

**No Apple developer account, signing certificate, or provisioning profile is
required.** Local builds use the toolchain's ad-hoc signature; the packaging script
adds hardened runtime with an ad-hoc signature. This is local distribution, not
notarization or App Store distribution.

## Build and start

```sh
swift test
scripts/package.sh
scripts/install.sh
export PATH="$HOME/.local/bin:$PATH"

# Choose a NEW recovery-file path. Its parent directory must already exist.
mop vault init --recovery-file "$HOME/mop-recovery.key" --name "My Mac"
mop write mop://personal/github/token
mop read mop://personal/github/token
```

`write` reads a hidden terminal prompt, or UTF-8 stdin for multiline values. It
never accepts a secret as an argument. Every command accessing secrets requires
fresh Touch ID or system password authentication. There is no software-key
fallback when the Secure Enclave is unavailable.

The default vault is `~/.mop/.mopfile`. The opaque device-key record is
`~/.mop/device.json`, with owner-only permissions. Local vault-key fingerprints live
in `~/.mop/trust/`; keep this directory on the Mac, outside cloud sync. Initialization
pins the newly created vault key automatically and prints its fingerprint. Save that
fingerprint with your offline recovery material. **Keep the recovery key offline,
separate from the vault.** It is a full alternative decryption capability, without
the original Mac's Secure Enclave or Touch ID. Moving it off the Mac protects
against losing all enrolled devices. Initialization never overwrites existing
vaults or recovery files; if a later initialization step fails, any recovery file
already written is retained.

The installer uses `~/.local/lib/mop/mop` and a `~/.local/bin/mop` symlink. For a
custom installation prefix, set `MOP_INSTALL_ROOT`. It refuses to replace unrelated
executables or symlinks. A previous `Mop.app` installation is left intact; its
known command symlink can be upgraded to the new CLI. Old Keychain entries are
not deleted or automatically migrated. Legacy Keychain source/checks remain in the
repository, but the new CLI neither links that backend nor needs its entitlements.

You can also run `swift run mop ...` directly. Preserve `device.json` across
rebuilds/upgrades; keys are bound to the hardware, not this binary's signing ID.

## Manpage and shell completions

`scripts/package.sh` includes the manpage and Bash, zsh, and Fish completions under
`dist/share/`. `scripts/install.sh` installs them alongside mop under `~/.local`
(or `MOP_INSTALL_ROOT`). Keep the executable and its sibling `share/` directory
together when passing a custom packaged executable to the installer. Installation
refuses to replace unrelated manpages or completion files, and upgrades managed
files. It does not edit shell startup files.

To make the manpage discoverable, add this to your shell startup file (Bash/zsh):

```sh
export MANPATH="$HOME/.local/share/man:${MANPATH:-}"
```

Then run `man mop`. The trailing default search path preserves system manuals.
You can also read the source directly with `man ./docs/man/mop.1` from this checkout.

For **zsh**, add the following to `~/.zshrc`, placing the `fpath` assignment before
your existing `compinit` call if your shell configuration already has one:

```zsh
fpath=("$HOME/.local/share/zsh/site-functions" $fpath)
autoload -Uz compinit
compinit
```

For **Bash**, add this to `~/.bashrc` (or `~/.bash_profile` for a macOS login shell):

```bash
source "$HOME/.local/share/bash-completion/completions/mop"
```

For **Fish**, the default installation uses its user vendor-completion directory,
`~/.local/share/fish/vendor_completions.d/mop.fish`. If that directory is not on
`$fish_complete_path`, add this to `~/.config/fish/config.fish`:

```fish
source "$HOME/.local/share/fish/vendor_completions.d/mop.fish"
```

For Fish manpage lookup, use `set -gx MANPATH "$HOME/.local/share/man" $MANPATH ''`.
Substitute your installation prefix in these paths when using `MOP_INSTALL_ROOT`.
See the [Fish completion search rules](https://fishshell.com/docs/current/completions.html#where-to-put-completions)
and [zsh initialization documentation](https://zsh.sourceforge.io/Doc/Release/Completion-System.html#Initialization).

You can also generate scripts directly, without installing or accessing a vault:

```sh
mop completion bash
mop completion zsh
mop completion fish
```

`mop --generate-completion-script SHELL` is equivalent. Completions cover nested
commands, options, shell names, and file/directory arguments. They do not enumerate
secrets, vault names, device fingerprints, or revision hashes, and do not trigger
Touch ID. Open a new shell after updating its configuration.

## iCloud Drive and other Macs

Select a file within your existing iCloud Drive folder:

```sh
export MOP_VAULT_FILE="$HOME/Library/Mobile Documents/com~apple~CloudDocs/mop/.mopfile"
mop vault init --recovery-file "$HOME/mop-icloud-recovery.key" --name "First Mac"
```

Initialize only once. On other Macs, select the same **synced file**, and enroll
their own keys instead of initializing another vault. `--vault-file PATH` overrides
`MOP_VAULT_FILE` on any operational subcommand. The local-key directory can be
selected using `--state-directory PATH` or `MOP_STATE_DIRECTORY`; never point it
at a cloud-synced directory. Device keys cannot be copied to another Mac.

On the new Mac:

```sh
mop device request --out "$HOME/new-mac-request.json" --name "Second Mac"
```

Transfer this public request to an authorized Mac. Compare the full displayed
fingerprint through a trusted channel, such as reading it directly from the new
Mac's screen. Then, on the authorized Mac:

```sh
mop device add --request new-mac-request.json --fingerprint FULL_SHA256_FINGERPRINT
mop device list
```

On the authorizing Mac, obtain the **vault** fingerprint (distinct from the device
fingerprint):

```sh
mop vault fingerprint
```

After the updated file reaches the new Mac, compare that fingerprint through a
trusted channel, then pin it locally:

```sh
mop vault trust --fingerprint FULL_VAULT_FINGERPRINT
```

The new Mac can then read the vault with its own Touch ID/password. Missing or
mismatched local trust fails closed with code 16; decryptability alone does not
prove that the vault came from an authorized writer.

Device requests contain a public key and device name, not secret data; the device
fingerprint check guards against substitution. A request does not constitute
remote hardware attestation: approve only requests generated on devices you trust.

```sh
mop device remove FULL_SHA256_FINGERPRINT
```

Removing another device rotates the AES vault key and re-encrypts the current
vault for remaining devices and recovery. It updates the revoking Mac's local pin
and prints the new vault fingerprint. Every other remaining Mac must independently
verify and pin this new fingerprint with `mop vault trust --fingerprint ...` before
opening the updated vault. Save the new fingerprint with offline recovery material.
Removal does not erase old copies or make previously learned secrets unknown. You cannot remove the current device through
this command. There is a maximum of 63 devices plus one recovery recipient.

## Recovery

On a replacement Mac, select the synced vault and restore the offline recovery
file with owner-only permissions (`chmod 600`), then:

```sh
mop vault recover --recovery-file /path/to/mop-recovery.key --fingerprint FULL_VAULT_FINGERPRINT --name "Replacement Mac"
```

Recovery enrolls this Mac's Secure Enclave key and requires local authentication.
The fingerprint must come from a trusted Mac or your offline records, and must
match the current encryption key (it changes after device removal). If instead you
have a known-good vault backup, restore that copy and use `--revision SHA256` with
its independently recorded SHA-256 hash. The recovery private key alone cannot
prove the authenticity of a replaceable vault: anyone can encrypt to its public key.
Recovery refuses to implicitly trust a file just because it decrypts.
Return the recovery file to offline storage afterward. A device record from an
erased or different Mac may be unusable; preserve it elsewhere and use a new,
local `--state-directory` for recovery. The tool never silently replaces an
existing device record. Losing every usable device key **and** the recovery key
makes the vault unrecoverable.

## Secret commands

```sh
mop write mop://personal/github/token
mop write mop://personal/github/token --replace
secure-secret-source | mop write mop://personal/service/credential
mop read mop://personal/github/token --no-newline
mop list --vault personal
mop list --json
mop delete mop://personal/github/token
```

`read` supports `-n/--no-newline`. Both `read` and `inject` support
`-o/--out-file PATH`, `--file-mode OCTAL` (default `0600`), and `-f/--force`.
File-only options require `--out-file`; permissions may range from `0000` through
`0777`, without special bits. Existing files require `--force`; there is no overwrite
prompt. Files are written atomically only after all secrets resolve. Destination
symlinks, non-regular files, and the selected vault/history/device record/local trust
directory are rejected.
For deliberate in-place template replacement, specify the same input/output file
and `--force`. Plain shell redirection does not provide these safeguards.

```sh
mop read mop://personal/github/token -n -o token.txt
mop inject -i config.template -o config.generated --file-mode 0600
mop inject -i config.generated -o config.generated --force
```

`write` creates only; `--replace` updates only. Stdin preserves UTF-8 values exactly,
including empty values and trailing newlines. The hidden prompt takes one line,
up to 65,536 UTF-8 bytes. `read` appends one newline unless `--no-newline` is set.
`list --json` emits an array of references without values.

References have three or four case-sensitive, nonempty components:
`mop://vault/item/[section/]field`. A sectionless field and a field in a section
are distinct; for example, `mop://v/i/token` and `mop://v/i/api/token`.
Use letters, digits, `-._~` literally; percent-encode other UTF-8 bytes (for example,
`mop://personal/GitHub%20API/token`). Decode occurs once; names normalize to Unicode
NFC. Query strings, fragments, NUL, invalid UTF-8, and raw spaces are rejected.
Logical vault names are namespaces within the same encrypted file.

### Run and inject

```dotenv
GITHUB_TOKEN=mop://personal/github/token
APP_MODE=development
```

```sh
mop run --env-file dev.env -- your-program --its-option
mop run --env-file base.env --env-file local.env -- your-program
GITHUB_TOKEN=mop://personal/github/token mop run -- your-program
mop inject --in-file config.template > config.generated
```

Later dotenv files override earlier files and inherited variables; the last
assignment wins. Supported syntax is line-oriented `NAME=value`, single/double
quoted literal values, empty values, and comments. Inline comments start after
whitespace. There is no shell evaluation, general variable expansion, backslash unescaping,
`export` keyword, or quoted multiline syntax. Values starting with `mop://` must be
complete references; embedded references in larger environment values stay literal.
NUL cannot be placed in a process environment.

Templates use `{{ mop://personal/github/token }}`. Unrelated placeholders are
preserved. Replacement is literal, not JSON/YAML/shell escaping, and replacement
values are not recursively evaluated. Without `--in-file`, input comes from stdin.

Inside references only, `run` and `inject` expand `$NAME` and `${NAME}` once:

```dotenv
APP_ENV=development
TOKEN=mop://${APP_ENV}/github/api/token
```

`run` uses the merged environment after all dotenv overrides. `inject` uses the
inherited environment. Expansion applies to references even if the dotenv value
was quoted; other dotenv values remain literal. Substitutions are literal component
text: a variable containing `/` cannot change the reference's structure. Undefined
variables, malformed expressions, and empty resulting components fail before
authentication. There are no shell operators, defaults, recursive substitutions,
or expansion of fetched secrets. Use `%24` for a literal dollar sign in a reference.
Keep references shell-quoted when the expansion should happen inside mop.

All references resolve before output or child execution; repeats are fetched once.
Masking patterns retain distinct UTF-8 encodings even when Unicode strings are
canonically equivalent.
`run` requires `--` and never adds an implicit shell. By default it supervises the
child with inherited stdin and separate stdout/stderr pipes. Exact occurrences of
resolved, nonempty secret values become `[concealed by mop]`, including multiline
values and matches spanning reads. Matching is leftmost-longest and byte-based;
replacement text is not scanned again. Only fetched secret values are masked, not
arbitrary inherited environment values. Empty secrets are ignored, and short
secrets can conceal ordinary text too. Secret values remain in mop's process memory
while filtering output; the authentication context is closed before launch.

Pipes change `isatty`, buffering, color, and interactive program behavior. Use
`mop run --no-masking -- COMMAND` for direct `execve` execution with full terminal
and job-control behavior. Both modes preserve command arguments and exit status;
masked execution forwards termination signals to the immediate child. It does not
manage detached descendants. Masking cannot protect transformed/encoded secrets,
secrets written directly to files or `/dev/tty`, or deliberate bypasses by a child.

Shell output redirection can create/truncate a file before mop starts, even if mop
subsequently fails without producing output. Prefer `--out-file` for read/inject.

## Real-world examples

The [usage cookbook](docs/EXAMPLES.md) adapts 1Password's documented workflows to
mop: GitHub CLI tokens, local application dotenv files, Docker login through stdin,
temporary npm configuration, SSH passwords, and multiline private keys.

For `sshpass`, Bash/zsh process substitution supplies the password on a file
descriptor without exporting a long-lived password environment variable:

```bash
sshpass -d 3 ssh sshprofile 3< <(mop read mop://personal/sshprofile/password)
```

See [the sshpass recipe](docs/EXAMPLES.md#give-sshpass-a-password-through-file-descriptor-3)
for setup, descriptor lifetime, and asynchronous authentication behavior.

## File boundaries and upgrades

Each `.mopfile` has its own encryption key, recipient list, recovery credential,
and history. Logical vault names within that file are namespaces, not permissions.
Every enrolled device can access the entire file. Use different files for independent
access boundaries, selecting one file per command:

```sh
mop vault init --vault-file /path/to/personal.mopfile --recovery-file /offline/personal.key
mop vault init --vault-file /path/to/work.mopfile --recovery-file /offline/work.key
mop device add --vault-file /path/to/work.mopfile --request second-mac.json --fingerprint FULL_SHA256_FINGERPRINT
mop run --vault-file /path/to/work.mopfile --env-file work.env -- your-program
```

A device enrolled only in the work file receives no access to the personal file,
even if references have identical names. The same local device record may be used
with multiple independently enrolled files. There is no automatic cross-file routing.

The security update requires local trust for every file path. New vaults establish
it during initialization. There is no automatic trust-on-first-use for old files,
new state directories, or relocated vaults. A trusted Mac can provide the vault
fingerprint; alternatively, explicitly pin a known-good backup with
`mop vault trust --revision SHA256`. Never compute this approval hash only from the
untrusted synced file: doing so would accept an attacker's replacement. If neither
trusted evidence nor a trusted copy is available, create a new vault. Losing the
local trust records requires this same explicit verification again.

Version 0.3.0 reads `mop-vault-v1` and `mop-vault-v2`. New files use v2. Existing v1
files stay v1 during ordinary writes and upgrade atomically on their first
successful write of a sectioned field. The prior encrypted revision is preserved;
failed writes do not upgrade. Recovery and enrolled device keys continue to work.
History restoration never downgrades a v2 file, even when restoring v1 contents.
**Upgrade mop on every enrolled Mac before using sections:** older binaries cannot
open v2 files. Update scripts that require a terminal to use `run --no-masking`.

## Concurrent writes and conflicts

Reads and writes use macOS `NSFileCoordinator`; writes compare the exact encrypted
snapshot originally read and atomically replace it. A stale command fails with
code 11 rather than overwrite a newer value. Every update preserves the old and
new encrypted revisions in `.mopfile.history` beside the vault. Keep that directory
with the vault when moving or syncing it; it contains encrypted data only.

Known unresolved macOS file versions block ordinary reads and writes. To preserve
and examine candidate versions:

```sh
mop vault conflicts
# Each output line is a full revision hash. Inspect a candidate using normal commands.
# A history file has its own path: first trust its key using an independently
# recorded vault fingerprint for that revision (not a hash of the candidate itself).
mop vault trust --vault-file /path/to/.mopfile.history/HASH.moprevision --fingerprint TRUSTED_VAULT_FINGERPRINT
mop list --vault-file /path/to/.mopfile.history/HASH.moprevision
mop read mop://personal/github/token --vault-file /path/to/.mopfile.history/HASH.moprevision
mop vault resolve --revision HASH
```

Resolution authenticates and verifies both the current and selected snapshots,
restores the selected contents, and keeps the current recipient list and vault
key. The selected revision's key must also appear in this Mac's current or previous
trusted pins. History encrypted under an unknown key is rejected. It preserves
every known conflicting version before marking those versions
resolved. It does not automatically merge competing values. Never edit history
files directly; read them or explicitly restore their contents.

File coordination is **local**, not a distributed lock. iCloud sync is eventual;
offline Macs may independently create competing revisions. The implementation
handles conflicts reported through `NSFileVersion` and keeps immutable encrypted
history, but cannot guarantee detection of every provider's silent replacement or
of a malicious replay of an older, valid file. Live two-Mac iCloud conflict behavior
still needs validation. Sync the vault and its history and verify that both appear
on the other Mac before relying on them. History currently has no automatic pruning.

## Cryptographic design

See [Security and key management](docs/SECURITY.md) for the complete security model,
key/file inventory, authentication lifecycle, and device enrollment, revocation,
recovery, and replacement procedures. It also explains the difference between
device fingerprints, vault fingerprints, and revision hashes, including
[trust errors after an upgrade](docs/SECURITY.md#trust-errors-after-upgrades-or-moving-files).


- A local SHA-256 commitment to the vault UUID and 256-bit AES key is required
  before opening a vault, including recovery and conflict resolution. It contains
  no decryption key. An attacker controlling only the synced vault cannot replace
  the encryption key and have subsequent writes accepted. Pins are indexed by
  canonical file path in the private local state directory, so changing the UUID
  or moving a file cannot silently establish new trust. Key rotation updates the
  local pin; other Macs need an explicit trusted fingerprint comparison. The pin
  does not detect replay of an older valid revision using the same encryption key.
- Private file writes remove inherited ACLs before writing bytes. Private file and
  directory reads reject ACL allow entries in addition to checking owner/mode bits.
- AES-256-GCM encrypts the entire reference/value dictionary with a fresh random
  nonce on every update. Decoding is bounded to a 16 MiB envelope and writes to
  less than 8 MiB of plaintext.
- CryptoKit HPKE (`P256_SHA256_AES_GCM_256`) wraps the 32-byte vault key separately
  for each device and recovery public key. Vault identity, recipient fingerprint,
  role, and format are bound into HPKE context information.
- The format header, generation, parent hash, and complete recipient table are
  authenticated as AES-GCM associated data. Recipient names/public keys and revision
  metadata are visible; all secret names and values are encrypted.
- Each device's Secure Enclave P-256 key uses `WhenUnlockedThisDeviceOnly` plus
  `.privateKeyUsage` and `.userPresence`. Its opaque representation is stored in a
  local owner-only file. No raw device private key is exported.
- Every secret command creates a fresh `LAContext`, disables previous biometric
  reuse, authenticates, and then disallows additional authentication UI. Private-key
  access must succeed under that same context; no weaker retry is attempted.
- AES keys and decrypted values exist in process memory during the command. No
  persistent plaintext cache is used, but Swift does not guarantee erasing all
  copies of String/Data values. Any program possessing the local opaque key blob
  can attempt its use on this Mac, subject to the key's authentication constraints;
  this backend does not provide Keychain access-group isolation.

The recovery file is a high-entropy P-256 private key, not a password. It is an
intentional alternative access path. Revocation protects subsequent revisions,
not historical ciphertext. The design uses CryptoKit primitives; it has not had
an independent security audit.

See [Apple's Secure Enclave description](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[CryptoKit key-blob clarification](https://developer.apple.com/forums/thread/786223),
and [iCloud file coordination](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/iCloud/iCloud.html).

## Exit codes and validation

Diagnostics go to stderr and exclude secret values and arbitrary OS error text.

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Invalid CLI/reference/dotenv/template/process/output options |
| 3 | Authentication denied, cancelled, unavailable, or another prompt required |
| 4 | Secret field missing |
| 5 | Field, device enrollment, or output file already exists (output requires --force) |
| 6 / 8 | Reserved for legacy Keychain/signing errors |
| 7 | File/input/output failure or invalid UTF-8 |
| 9 | Vault/file missing |
| 10 | Invalid, unsupported, or unauthentic vault |
| 11 | Stale write or unresolved version conflict |
| 12 | Secure Enclave unavailable |
| 13 | Device not enrolled or not initialized |
| 14 | Invalid device/request/fingerprint/recovery key |
| 15 | Unsafe file type/permissions or protected output path |
| 16 | Missing or mismatched local vault-key trust |
| 126 / 127 | Program cannot execute / not found |

After successful `run`, the child program's status applies.

```sh
swift test
scripts/package.sh
python3 scripts/smoke-test.py dist/mop
python3 scripts/test-tooling.py dist/mop
python3 scripts/test-shell-support.py dist/mop
```

See [docs/VALIDATION.md](docs/VALIDATION.md) for observed hardware results and the
remaining multi-Mac checks. `mop-enclave-check` is a separate, opt-in disposable
hardware probe; normal tests do not prompt or create device keys.
