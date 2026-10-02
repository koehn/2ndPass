#!/usr/bin/env python3
"""Offline release archive validation; no signing or notarization claims."""
import importlib.util
from pathlib import Path
import plistlib
import tempfile
import subprocess
import zipfile

spec = importlib.util.spec_from_file_location('cask', Path(__file__).with_name('prepare-cli-cask.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as directory:
    archive = Path(directory) / 'release.zip'
    base = 'cli/2ndPass CLI.app/Contents/'
    with zipfile.ZipFile(archive, 'w') as out:
        out.writestr(base + 'Info.plist', plistlib.dumps({'CFBundleExecutable': 'sp', 'CFBundleIdentifier': 'net.test.mop.CLI', 'CFBundleShortVersionString': '0.7.0'}))
        for name in (base + 'MacOS/sp', base + 'embedded.provisionprofile', base + '_CodeSignature/CodeResources',
                     'cli/install-cli.sh', 'cli/LICENSE', 'cli/share/man/man1/sp.1',
                     'cli/share/bash-completion/completions/sp', 'cli/share/zsh/site-functions/_sp',
                     'cli/share/fish/vendor_completions.d/sp.fish'):
            out.writestr(name, 'fixture')
    result = m.generate('0.7.0', 'https://example.com/cli.zip', archive)
    assert m.hashlib.sha256(archive.read_bytes()).hexdigest() in result
    assert 'binary "cli/2ndPass CLI.app/Contents/MacOS/sp"' in result
    assert '\n  app ' not in result
    cask = Path(directory) / 'secondpass-cli.rb'
    cask.write_text(result)
    subprocess.run(['ruby', '-c', str(cask)], check=True)
    for version, url in [('0.8.0', 'https://example.com/cli.zip'), ('0.7.0', 'https://example.com/#{system("bad")}')]:
        try: m.generate(version, url, archive)
        except ValueError: pass
        else: raise AssertionError('invalid metadata accepted')
print('PASS: CLI cask archive validation, checksum, layout, and metadata rejection.')
