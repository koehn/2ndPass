#!/usr/bin/env python3
"""Exercise local installation under temporary prefixes; no real user install."""
import os
import pathlib
import subprocess
import sys
import tempfile

app = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'dist/Mop.app').resolve()
root = pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='mop-install-test-') as directory:
    prefix = pathlib.Path(directory) / 'prefix'
    environment = os.environ | {'MOP_INSTALL_ROOT': str(prefix)}
    command = [str(root / 'scripts/install.sh'), str(app)]
    subprocess.run(command, env=environment, check=True, capture_output=True)
    link = prefix / 'bin/mop'
    assert link.is_symlink()
    assert (prefix / 'lib/mop/Mop.app/Contents/embedded.provisionprofile').is_file()
    direct = prefix / 'lib/mop/Mop.app/Contents/MacOS/mop'
    identity = subprocess.check_output([str(direct), 'device', 'identity']).strip()
    assert identity
    assert subprocess.check_output([str(link), 'device', 'identity']).strip() == identity
    # A relative symlink chain must identify the same signed application too.
    alias = prefix / 'bin/mop-alias'
    alias.symlink_to('mop')
    assert subprocess.check_output([str(alias), 'device', 'identity']).strip() == identity
    assert subprocess.check_output([str(link), '--version']).strip() == b'0.3.0'
    resources = ['man/man1/mop.1', 'bash-completion/completions/mop',
                 'zsh/site-functions/_mop', 'fish/vendor_completions.d/mop.fish']
    for resource in resources:
        installed = prefix / 'share' / resource
        assert installed.is_symlink() and installed.is_file()
        assert installed.read_bytes() == (app.parent / 'share' / resource).read_bytes()
    subprocess.run(command, env=environment, check=True, capture_output=True)
    for resource in resources:
        installed = prefix / 'share' / resource
        expected = installed.readlink()
        installed.unlink()
        installed.write_text('unrelated resource')
        assert subprocess.run(command, env=environment, capture_output=True).returncode == 7
        assert installed.read_text() == 'unrelated resource'
        installed.unlink()
        installed.symlink_to('/dev/null')
        assert subprocess.run(command, env=environment, capture_output=True).returncode == 7
        assert installed.readlink() == pathlib.Path('/dev/null')
        installed.unlink()
        installed.symlink_to(expected)
    link.unlink()
    link.write_text('unrelated file')
    assert subprocess.run(command, env=environment, capture_output=True).returncode == 7
    assert link.read_text() == 'unrelated file'
    link.unlink()
    link.symlink_to('/bin/echo')
    assert subprocess.run(command, env=environment, capture_output=True).returncode == 7
    assert link.readlink() == pathlib.Path('/bin/echo')
print('PASS: fresh install, executable link, upgrade, file collision, and symlink collision, including manpage and completions.')
