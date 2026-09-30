# Releasing 2ndPass

The public app name is **2ndPass**, its executable is `sp`, and its domain is
`2ndpass.app`. The repository is at `github.com/koehn/2ndPass`.

These release procedures are for the copyright holder and separately authorized maintainers. The [copyright notice](../LICENSE) permits public inspection and analysis only.

## Signed application releases

Follow the [signed build instructions](../README.md#build-and-provision) and
[mobile distribution guide](MOBILE.md). Packaging produces `dist/2ndPass.app`
and shell resources. `scripts/install.sh` installs `/Applications/2ndPass.app`
and `/usr/local/bin/sp`.

Keep the existing bundle ID, Keychain groups, CloudKit container, and environment
consistent across Mac/mobile builds and updates. The branding change does not
migrate identities or vault formats. The separate v7 cutover has no v6 reader or migration. See [branding and identity](BRANDING.md).

Before release, update versions and complete the current checks in
[validation](VAULT-NEXT-VALIDATION.md), including the outstanding physical-device,
AutoFill, recovery, cross-account sharing, and Production CloudKit acceptance.
Historical audit results do not establish current release readiness. 2ndPass has
not yet received an independent security audit. Review both protocol correctness
and implementation correctness; source availability is not a substitute. The
[documentation audit](security-audit/2026-09-29-documentation.md) lists trust-boundary
questions for acceptance and the eventual auditor.

## Homebrew development formula

`Formula/secondpass.rb` is currently HEAD-only and installs an ad-hoc CLI for
non-secret development checks. It is not the supported vault distribution.
`Formula/mop.rb` preserves the historical stable release. A future supported
Homebrew distribution must retain the signed and provisioned app bundle.

The [Homebrew workflow](../.github/workflows/homebrew.yml) stages a local archive
of the reviewed commit, then checks compilation, CLI behavior, completions,
and the manpage. It does not validate signing or hardware access.

After publishing a compatible source tag, maintainers can prepare metadata for
the development formula with:

```sh
python3 scripts/prepare-homebrew-release.py vMAJOR.MINOR.PATCH --license cannot_represent
python3 scripts/test-homebrew-release.py
```

The script verifies the CLI version and computes the archive checksum. It does
not publish anything. Review its output before committing. Keep published tags
immutable and keep the source-only formula clearly labeled as a development tool.
