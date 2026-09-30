# Homebrew and 2ndPass

The supported way to access current vaults is the [signed application build](../README.md#signed-source-build).
The application and CLI require a provisioned bundle with CloudKit, App Groups,
and Keychain access. An ad-hoc Homebrew executable cannot access those keys.

## Developer CLI build

`Formula/secondpass.rb` builds the renamed CLI from HEAD. Until a renamed release
is published, there is no stable 2ndPass source archive. This formula is useful
for development and non-secret CLI checks, not as a working vault installation.

```sh
brew tap koehn/mop https://github.com/koehn/mop
brew install --HEAD koehn/mop/secondpass
sp --help
man sp
brew test koehn/mop/secondpass
```

The formula name is `secondpass`; the executable is `sp`. The existing GitHub
repository and tap still use `mop`. `Formula/mop.rb` remains pinned to the historical
0.3.0 release and does not track HEAD.

A future supported Homebrew distribution should install the signed, provisioned
app bundle, for example through a cask. See [release guidance](RELEASING.md).

Uninstalling the developer CLI (`brew uninstall secondpass`) does not delete vaults
or device keys. Do not remove existing Mop application-support directories or
change signing identifiers as part of the rename; see [branding and identity](BRANDING.md).
