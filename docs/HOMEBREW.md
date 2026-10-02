# Homebrew and 2ndPass

The supported CLI distribution is a signed, provisioned, notarized universal
macOS bundle, separate from the sandboxed GUI. `sp ssh-agent` is included in `sp`.
The GUI and CLI can be installed and upgraded independently. The CLI retains
its normal shell, process-inspection, and SSH-agent capabilities.

## Build and install directly

Register `com.koehn.mop.CLI` as a separate macOS App ID. Its profile must authorize:

- Keychain access group `<AppIdentifierPrefix>com.koehn.mop` (the existing host
  group, not a new `.CLI` group).
- App Group `group.com.koehn.mop`.
- CloudKit container `iCloud.com.koehn.mop`, the selected environment, and existing
  KVS identifier `<TeamID>.com.koehn.mop`.

Use the same signing team and identifier prefix as the GUI. The CLI does not need
AutoFill Provider or App Sandbox entitlements. It does not publish system AutoFill
suggestions; open/refresh the GUI after editing credentials through the CLI.

```sh
export MOP_SIGN_IDENTITY='Developer ID Application: Your Organization (TEAMID)'
export MOP_CLI_PROVISION_PROFILE='/path/to/CLI.provisionprofile'
export MOP_CLOUD_ENVIRONMENT=Production
scripts/package-cli.sh
scripts/install-cli.sh
```

The installer keeps `2ndPass CLI.app` under `/usr/local/lib/sp`, links
`/usr/local/bin/sp`, and installs manpage/completion links under `/usr/local/share`.
Set `MOP_INSTALL_ROOT` for another prefix. Run as your normal user; installation
requests administrator access only if necessary. The installer never replaces the
GUI. An existing link into `/Applications/2ndPass.app` can be migrated by installing
the CLI **before** upgrading the GUI. Keep the signed CLI bundle intact.

## Prepare a Homebrew release

Configure a `notarytool` Keychain profile, then run:

```sh
export MOP_NOTARY_PROFILE='your-notary-profile'
scripts/prepare-cli-release.sh 0.7.0 \
  https://github.com/koehn/2ndPass/releases/download/v0.7.0/secondpass-cli-0.7.0-macos-universal.zip
```

This checks the version, Developer ID signature, and both architectures; submits
for notarization; staples and assesses the bundle; then produces the ZIP and
`dist/Casks/secondpass-cli.rb` with its actual SHA-256. Nothing is uploaded to
GitHub or published to Homebrew. The supplied URL must be where that exact ZIP
will be uploaded. The standalone cask generator validates archive structure and
metadata; only the release script performs signing/notarization checks.

Publish the archive and copy the generated cask into `Casks/secondpass-cli.rb` in
your tap. Then users can run:

```sh
brew tap koehn/2ndpass https://github.com/koehn/2ndPass
brew install --cask koehn/2ndpass/secondpass-cli
```

The cask keeps the bundle in Homebrew's Caskroom and links `sp` and shell resources;
it does not install or overwrite an app in `/Applications`. Remove a conflicting
old CLI installation/link before switching installers. Neither normal cask removal
nor the direct installer deletes vault data or Keychain identities. No `zap` stanza
removes shared vault state.

The existing `Formula/secondpass.rb` remains a source-development formula; its
ad-hoc build cannot access production vault keys. `Formula/mop.rb` describes the
historical release. Do not use the source-formula release helper for signed CLI
releases. Current source remains inspection-only under the repository LICENSE;
release publication requires the copyright holder's authorization.

## Acceptance checks

Run `scripts/test-signing-config.py`, `scripts/test-install-layout.py`,
`scripts/test-gui-install.py`, and `scripts/test-cli-cask.py` offline. Run `scripts/test-tooling.py` against the signed
CLI bundle for real signature, symlink, and tampering checks. Before publication,
verify an existing vault and device identity from both GUI and CLI, AutoFill,
concurrent access, upgrades, SSH approvals, and recovery on a physical Mac.
