#!/usr/bin/env python3
"""Generate a Homebrew cask for a local signed CLI release archive; never publish."""
import argparse
import hashlib
from pathlib import Path
import plistlib
import re
import zipfile


def generate(version, url, archive):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('expected MAJOR.MINOR.PATCH')
    # Restrict Ruby-interpolated metadata to literal HTTPS URLs.
    if not re.fullmatch(r'https://[A-Za-z0-9._~:/%+?=&-]+', url):
        raise ValueError('expected a literal HTTPS archive URL')
    with zipfile.ZipFile(archive) as source:
        base = 'cli/2ndPass CLI.app/Contents/'
        info = plistlib.loads(source.read(base + 'Info.plist'))
        if info.get('CFBundleExecutable') != 'sp' or not info.get('CFBundleIdentifier', '').endswith('.CLI'):
            raise ValueError('expected a separate CLI bundle')
        if info.get('CFBundleShortVersionString') != version:
            raise ValueError('archive version mismatch')
        for name in (base + 'MacOS/sp', base + 'embedded.provisionprofile',
                     base + '_CodeSignature/CodeResources', 'cli/install-cli.sh', 'cli/LICENSE',
                     'cli/share/man/man1/sp.1', 'cli/share/bash-completion/completions/sp',
                     'cli/share/zsh/site-functions/_sp', 'cli/share/fish/vendor_completions.d/sp.fish'):
            source.getinfo(name)
    digest = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
    return f'''cask "secondpass-cli" do
  version "{version}"
  sha256 "{digest}"

  url "{url}"
  name "2ndPass CLI"
  desc "Signed vault command-line tools and SSH agent for 2ndPass"
  homepage "https://2ndpass.app"

  depends_on macos: ">= :sequoia"

  # Keep the provisioned bundle intact in the Caskroom; do not install a GUI.
  binary "cli/2ndPass CLI.app/Contents/MacOS/sp", target: "sp"
  manpage "cli/share/man/man1/sp.1"
  bash_completion "cli/share/bash-completion/completions/sp"
  zsh_completion "cli/share/zsh/site-functions/_sp"
  fish_completion "cli/share/fish/vendor_completions.d/sp.fish"
end
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('url')
    parser.add_argument('archive', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = generate(args.version, args.url, args.archive)
    args.output.write_text(result)


if __name__ == '__main__':
    main()
