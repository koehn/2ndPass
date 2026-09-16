# Installing with Homebrew

mop requires macOS 15 or later and Xcode 16 or later to build. To access secrets,
you also need Secure Enclave hardware and an interactive login session.

## Install

```sh
brew tap koehn/mop https://github.com/koehn/mop
brew install koehn/mop/mop
```

Homebrew builds mop from source and installs the executable, manpage, and Bash,
zsh, and Fish completions. Run `man mop` for the command reference, or follow the
[getting-started instructions](../README.md#create-a-vault) to create a vault.

If you previously installed mop from source, check which copy your shell uses:

```sh
type -a mop
```

An older copy in `~/.local/bin` may take precedence over the Homebrew installation.

## Shell completions

Follow the [shell completion setup](../README.md#manpage-and-shell-completions).
The same instructions work for Homebrew and source installations.

## Upgrade

```sh
brew update
brew upgrade koehn/mop/mop
```

Keep your `~/.mop` directory when upgrading. It contains your default vault,
device key record, and trusted vault fingerprints. If you share a vault between
Macs, check the [upgrade notes](../README.md#file-boundaries-and-upgrades) before
using a new file format.

## Check the installation

```sh
mop --version
brew test koehn/mop/mop
```

The Homebrew test checks command execution and installed files without opening
your vault or prompting for authentication.

## Uninstall

```sh
brew uninstall mop
brew untap koehn/mop
```

Uninstalling removes the program and its documentation. Your vaults, recovery
files, and local device records remain in place.

## Development builds

To install the latest source from `main`:

```sh
brew install --HEAD koehn/mop/mop
```

Development builds may contain changes that have not been released. Maintainers
can find packaging and release instructions in [Releasing mop](RELEASING.md).
