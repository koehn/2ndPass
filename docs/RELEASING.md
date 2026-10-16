# Releasing 2ndPass

The public app name is **2ndPass**, its executable is `sp`, and its domain is
`2ndpass.app`. The repository is at `github.com/koehn/2ndPass`.

These release procedures are for the copyright holder and separately authorized maintainers. The [copyright notice](../LICENSE) permits public inspection and analysis only.

## Signed application releases

Follow the [signed build instructions](../README.md#build-and-provision) and
[mobile distribution guide](MOBILE.md). Packaging produces `dist/2ndPass.app`
without a CLI. `scripts/install.sh` installs `/Applications/2ndPass.app`.
`scripts/package-cli.sh` separately produces `dist/cli/2ndPass CLI.app` and shell
resources; `scripts/install-cli.sh` installs them independently. See
[Homebrew releases](HOMEBREW.md) for CLI profiles, notarization, and cask generation.

Keep the existing bundle ID, Keychain groups, CloudKit container, and environment
consistent across Mac/mobile builds and updates. The branding change does not
migrate identities or vault formats. See [branding and identity](BRANDING.md).

Before release, update versions and complete the current checks in
[validation](VALIDATION.md), including the outstanding physical-device,
AutoFill, recovery, removal/deletion, and Production CloudKit acceptance.
Historical audit results do not establish current release readiness. 2ndPass has
not yet received an independent security audit. Review both protocol correctness
and implementation correctness; source availability is not a substitute.
Source formulas and their release helpers have been retired. Distribute the CLI
through the signed, notarized app bundle and generated cask described in
[Homebrew releases](HOMEBREW.md). Ordinary macOS CI checks Swift, packaging,
shell integration and documentation without installing a source formula.
