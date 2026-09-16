# Homebrew distribution

## Current status

`Formula/mop.rb` serves both the project tap and a future Homebrew core submission.
The initial formula installs the immutable GitHub source snapshot
`38a1cccd7ea18794a04ac5cff6f571cc92a9d29f` (CLI version 0.3.0), with a verified
SHA-256. It is not yet a tagged stable release. Mop is licensed under the
[MIT License](../LICENSE). The pinned snapshot predates the license file; the next
tagged release must include it before submission to core.
Nothing in the release tooling submits a pull request or publishes a release.

## Use this repository as a tap

Once the formula is committed and pushed to `koehn/mop`:

```sh
brew tap koehn/mop https://github.com/koehn/mop
brew install koehn/mop/mop
brew test koehn/mop/mop
```

The explicit repository URL is necessary because this repository is named `mop`,
not Homebrew's conventional `homebrew-mop`. No second GitHub repository is needed.
Subsequent updates use `brew update` and `brew upgrade koehn/mop/mop`.
`brew install --HEAD koehn/mop/mop` is available for development builds.

Installation currently builds from source and requires Xcode 16+ and macOS 15+.
Secret operations also require Secure Enclave hardware (Apple Silicon or a
supported Intel Mac with T2) and an interactive login session. Build success on
an Intel or virtual machine does not prove Secure Enclave support.

Homebrew installs the executable, manpage, and Bash/zsh/Fish completions in its
own prefix. It does not run `scripts/install.sh`, initialize a vault, prompt for
authentication, or move user data. Existing `~/.mop` state remains in place across
upgrades and uninstall. If you previously installed into `~/.local`, use `type -a
mop` to check which executable your shell finds first.

## Prepare a stable release

Mop uses the MIT License. Include `LICENSE` in every source release and use
`--license MIT` when preparing the formula. The script checks that the release
includes a license file; the maintainer must verify that its contents match the
supplied identifier.

1. Update the CLI version, README, manpage, and version assertions in the tests.
   Use a version newer than the initial 0.3.0 snapshot, for example 0.3.1, so
   existing tap installations receive an ordinary upgrade.
2. Run the project's tests and packaging checks. Commit and push the source,
   including `LICENSE` and `Package.resolved`, then tag the reviewed commit and
   publish a stable GitHub release. Do not move a published tag.
3. Generate the formula metadata from that published archive:

   ```sh
   python3 scripts/prepare-homebrew-release.py v0.3.1 --license MIT
   ```

   This downloads the exact archive, checks the CLI version against the tag,
   requires `LICENSE` and `Package.resolved`, computes SHA-256, and replaces the
   snapshot metadata with the release URL and license. It leaves build and test
   logic intact. A missing tag/file or version mismatch leaves the formula intact.
4. Validate the changed formula in a local tap, review the diff, then commit and
   push the formula update. Users receive it through `brew update`.

   ```sh
   brew tap-new --no-git koehn/mop-local
   cp Formula/mop.rb "$(brew --repository)/Library/Taps/koehn/homebrew-mop-local/Formula/mop.rb"
   brew style koehn/mop-local/mop
   brew install --build-from-source koehn/mop-local/mop
   brew test koehn/mop-local/mop
   brew audit --strict --online koehn/mop-local/mop
   brew linkage --test koehn/mop-local/mop
   ```

   Use `brew reinstall --build-from-source` if mop is already installed. Avoid
   keeping multiple mop taps installed at once; use fully qualified names.

## CI and hardware validation

`.github/workflows/homebrew.yml` builds and tests the exact commit under review
on Apple Silicon and Intel macOS 15 runners. Only the temporary CI formula's
source URL/checksum is replaced with a local archive; the committed formula keeps
its immutable public source. CI checks style, installation, linkage, the formula
functional tests, CLI smoke tests, and installed shell support. It has read-only
repository permissions and does not publish anything.

The formula uses Swift's locked dependency resolution and disables the SwiftPM
sandbox inside Homebrew's build sandbox. It installs only the main executable,
adds the same ad-hoc hardened-runtime signature as the packaging script, and
verifies it. Developer ID signing and notarization are not part of this source
build distribution.

The formula test exercises template processing, dotenv loading/child execution,
and a missing-vault error without opening a real vault or prompting for Touch ID.
It also verifies the installed resources and signature. CI cannot exercise the
Secure Enclave or interactive authentication. Before a public release, manually
verify creating a disposable vault, reading/writing, and continued access after
`brew reinstall`/`brew upgrade` on supported hardware. See [VALIDATION.md](VALIDATION.md)
for the broader hardware and multi-Mac checks.

## Local packaging validation

On 2026-09-16, the pinned snapshot was built and installed through a temporary
Homebrew tap on Apple Silicon with Swift 6.4. Formula style, `brew test`, strict
online tap audit, linkage checks, 78 CLI smoke checks, installed manpage/Bash/zsh
checks, and three release-preparation tests passed. Fish completion contents were
checked, but Fish runtime validation was skipped because Fish was unavailable.
The original `dist/` resource layout also passed its checks. The temporary tap and
installation were removed afterward. Hosted CI and interactive hardware upgrade
checks have not yet run. A passing tap audit is not a core eligibility approval.

## Prepare for homebrew/core (do not submit yet)

After the stable-release steps, the same formula can be copied to
`Formula/m/mop.rb` in a local `homebrew/core` checkout. There is no separate
formula template to drift out of sync. Before opening any submission:

- Ensure the tagged archive includes `LICENSE` and the formula declares `license "MIT"`.
- Confirm the release is stable, publicly downloadable, and reproducible without
  local caches. Recheck the current platform matrix, dependency rules, naming
  conflicts (`brew search mop`), and any existing submission.
- Run `brew style`, `brew audit --new --strict --online`, a source installation,
  `brew test`, and `brew linkage --test` against the local core formula, with
  `HOMEBREW_NO_INSTALL_FROM_API=1`. The current untagged snapshot predates `LICENSE`;
  replace it with a stable release archive containing the license before submission.
- Establish eligibility under Homebrew's current public-interest and maintenance
  policy. Technical readiness does not guarantee acceptance. Recheck the policy
  when submission is actually being considered.
- Let Homebrew's submission workflow generate official bottles. Do not copy
  guessed bottle checksums or third-party bottles into a core submission.

The tap remains useful while core eligibility is pending. Neither the workflow
nor the preparation script opens a core PR automatically.

References: [tap maintenance](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap),
[formula cookbook](https://docs.brew.sh/Formula-Cookbook),
[formula requirements](https://docs.brew.sh/Acceptable-Formulae),
[acceptance policy](https://docs.brew.sh/Package-Acceptance-Policy), and
[MIT license](https://opensource.org/license/mit).
