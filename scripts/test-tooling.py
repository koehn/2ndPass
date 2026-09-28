#!/usr/bin/env python3
"""Exercise local installation under temporary prefixes; no real user install."""
import os
import pathlib
import plistlib
import shutil
import signal
import subprocess
import sys
import tempfile

app = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'dist/2ndPass.app').resolve()
root = pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='2ndpass-install-test-') as directory:
    prefix = pathlib.Path(directory) / 'prefix'
    applications = pathlib.Path(directory) / 'Applications'
    environment = os.environ | {'MOP_INSTALL_ROOT': str(prefix), 'MOP_APPLICATIONS_DIR': str(applications)}
    command = [str(root / 'scripts/install.sh'), str(app)]
    subprocess.run(command, env=environment, check=True, capture_output=True)
    link = prefix / 'bin/2ndpass'
    assert link.is_symlink()
    assert link.readlink() == applications / '2ndPass.app/Contents/MacOS/2ndpass'
    assert (applications / '2ndPass.app/Contents/embedded.provisionprofile').is_file()
    info = plistlib.loads((applications / '2ndPass.app/Contents/Info.plist').read_bytes())
    assert info['CFBundleExecutable'] == 'MopApp'
    assert (applications / '2ndPass.app/Contents/MacOS/MopApp').is_file()
    resources_dir = applications / '2ndPass.app/Contents/Resources'
    assert (resources_dir / 'zxcvbn_zxcvbn.bundle').is_dir()
    assert (resources_dir / 'zxcvbn-LICENSE.txt').is_file()
    direct = applications / '2ndPass.app/Contents/MacOS/2ndpass'
    identity = subprocess.check_output([str(direct), 'device', 'identity']).strip()
    assert identity
    assert subprocess.check_output([str(link), 'device', 'identity']).strip() == identity
    # A relative symlink chain must identify the same signed application too.
    alias = prefix / 'bin/2ndpass-alias'
    alias.symlink_to('2ndpass')
    assert subprocess.check_output([str(alias), 'device', 'identity']).strip() == identity
    assert subprocess.check_output([str(link), '--version']).strip() == b'0.7.0'
    resources = ['man/man1/2ndpass.1', 'bash-completion/completions/2ndpass',
                 'zsh/site-functions/_2ndpass', 'fish/vendor_completions.d/2ndpass.fish']
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
    # The nested CLI must reject a tampered enclosing app even though its own
    # executable signature has not changed.
    tampered = pathlib.Path(directory) / 'Tampered.app'
    shutil.copytree(app, tampered)
    info_path = tampered / 'Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info['CFBundleDisplayName'] = 'Tampered'
    info_path.write_bytes(plistlib.dumps(info))
    rejected = subprocess.run([str(tampered / 'Contents/MacOS/2ndpass'), 'device', 'identity'], capture_output=True)
    # macOS may kill the process before our own signing check can return 8.
    assert rejected.returncode in (8, -signal.SIGKILL), (rejected.returncode, rejected.stderr)
    assert not rejected.stdout
    link.unlink()
    link.write_text('unrelated file')
    assert subprocess.run(command, env=environment, capture_output=True).returncode == 7
    assert link.read_text() == 'unrelated file'
    link.unlink()
    link.symlink_to('/bin/echo')
    assert subprocess.run(command, env=environment, capture_output=True).returncode == 7
    assert link.readlink() == pathlib.Path('/bin/echo')
print('PASS: fresh install, executable link, upgrade, file collision, and symlink collision, including native app, tampered-bundle rejection, manpage, and completions.')
