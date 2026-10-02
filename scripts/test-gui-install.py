#!/usr/bin/env python3
"""GUI-only installer isolation and rollback; code signing is stubbed."""
import os
from pathlib import Path
import subprocess
import tempfile

script = Path(__file__).with_name('install.sh').resolve()
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source = root / 'source.app'
    (source / 'Contents/MacOS').mkdir(parents=True)
    (source / 'Contents/MacOS/MopApp').touch()
    (source / 'valid').touch()
    stubs = root / 'bin'
    stubs.mkdir()
    signing = stubs / 'codesign'
    signing.write_text('''#!/bin/bash
if [[ "$1" == -d ]]; then
 echo Identifier=net.test.mop
 echo TeamIdentifier=TEST
else
 [[ -f "$3/valid" ]] || exit 8
 if [[ "$3" == "$FAIL_INSTALLED" && ! -f "$3/old" ]]; then exit 8; fi
fi
''')
    signing.chmod(0o755)
    apps = root / 'Applications'
    installed = apps / '2ndPass.app'
    cli = root / 'prefix/bin/sp'
    cli.parent.mkdir(parents=True)
    cli.write_text('existing CLI')
    env = os.environ | {'PATH': str(stubs) + ':' + os.environ['PATH'], 'MOP_APPLICATIONS_DIR': str(apps), 'MOP_INSTALL_ROOT': str(root / 'prefix')}
    def run(extra=None):
        return subprocess.run(['bash', str(script), str(source)], env=env | (extra or {}), capture_output=True)
    assert run().returncode == 0
    assert cli.read_text() == 'existing CLI'
    (installed / 'old').touch()
    assert run({'FAIL_INSTALLED': str(installed)}).returncode != 0
    assert (installed / 'old').exists()
    assert run().returncode == 0
    assert not (installed / 'old').exists()
    (source / 'Contents/MacOS/sp').touch()
    assert run().returncode == 7
print('PASS: GUI-only installation, CLI isolation, rollback, and combined-bundle rejection (signing stubbed).')
