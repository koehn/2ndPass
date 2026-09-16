# Releasing mop

Run the commands in this guide from a source checkout. Release scripts and tests
are repository tools, not part of the installed CLI.

The project repository also serves as the Homebrew tap. Its formula is
[`Formula/mop.rb`](../Formula/mop.rb); users receive formula updates through
`brew update`.

## Release checklist

1. Update the CLI version, README, manpage, and version assertions in the tests.
2. Run the [automated and hardware checks](VALIDATION.md). Verify access to a
   disposable vault before and after a Homebrew upgrade.
3. Commit the release source, including `LICENSE` and `Package.resolved`. Push
   the commit, tag it as `vMAJOR.MINOR.PATCH`, and publish a stable GitHub release.
   Keep published tags immutable.
4. Update the formula from the published archive:

   ```sh
   python3 scripts/prepare-homebrew-release.py v0.3.1 --license MIT
   ```

   Replace `v0.3.1` with the release tag. The script checks the CLI version,
   requires the license and dependency lockfile, and computes the archive's
   SHA-256. Review the resulting formula before committing it.
5. Validate the formula, then commit and push it to the tap.

The initial formula packages commit `38a1cccd7ea18794a04ac5cff6f571cc92a9d29f`
as version 0.3.0. The first tagged release should use a higher version so existing
installations receive the upgrade. That snapshot predates `LICENSE`; include the
license in the tagged source archive.

## Test the formula locally

Create a temporary tap and copy the formula into it:

```sh
brew tap-new --no-git koehn/mop-local
cp Formula/mop.rb "$(brew --repository)/Library/Taps/koehn/homebrew-mop-local/Formula/mop.rb"
brew style koehn/mop-local/mop
brew install --build-from-source koehn/mop-local/mop
brew test koehn/mop-local/mop
brew audit --strict --online koehn/mop-local/mop
brew linkage --test koehn/mop-local/mop
```

Use `brew reinstall --build-from-source koehn/mop-local/mop` if mop is already
installed. Use fully qualified formula names when working with multiple taps.
Remove the test installation and tap when finished:

```sh
brew uninstall koehn/mop-local/mop
brew untap koehn/mop-local
```

The formula uses locked Swift dependencies and installs an ad-hoc-signed release
binary, manpage, and generated completions. It bypasses `scripts/install.sh` so
Homebrew manages the installation paths.

## CI

The [Homebrew workflow](../.github/workflows/homebrew.yml) tests the commit under
review on Apple Silicon and Intel macOS 15 runners. It checks formula style,
source installation, linkage, CLI behavior, and shell support. The release script
also has offline tests:

```sh
python3 scripts/test-homebrew-release.py
```

CI uses a local source archive in a temporary formula. It cannot verify Secure
Enclave access or interactive authentication; those need hardware testing.

## Homebrew core

The tap formula can also be used for a future core submission at
`Formula/m/mop.rb`. Before submitting:

- Package a stable tagged release containing `LICENSE`, with `license "MIT"`
  declared in the formula.
- Check Homebrew's current platform and dependency requirements, naming conflicts
  (`brew search mop`), and existing submissions.
- Test the formula in a local core checkout with `HOMEBREW_NO_INSTALL_FROM_API=1`.
  Run `brew style`, `brew audit --new --strict --online`, a source installation,
  `brew test`, and `brew linkage --test`.
- Check the project's eligibility under Homebrew's public-interest and
  maintenance requirements.

Official bottles are generated through Homebrew's submission workflow.

See the [formula cookbook](https://docs.brew.sh/Formula-Cookbook),
[formula requirements](https://docs.brew.sh/Acceptable-Formulae), and
[package acceptance policy](https://docs.brew.sh/Package-Acceptance-Policy).
