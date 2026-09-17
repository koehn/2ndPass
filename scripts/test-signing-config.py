#!/usr/bin/env python3
"""Validate signing configuration generation without identities or Keychain access."""
import copy
import datetime
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile

script = Path(__file__).with_name('signing-config.py')
base = {'ExpirationDate': datetime.datetime.now() + datetime.timedelta(days=1),
        'Entitlements': {'com.apple.application-identifier': 'TEAM.net.test.mop',
                         'com.apple.developer.team-identifier': 'TEAM',
                         'keychain-access-groups': ['TEAM.*'], 'get-task-allow': True}}
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    def generate(profile):
        (root / 'profile').write_bytes(plistlib.dumps(profile))
        return subprocess.run([sys.executable, str(script), str(root / 'profile'),
                               'net.test.mop', 'mop', str(root / 'info'), str(root / 'entitlements')],
                              capture_output=True)
    assert generate(base).returncode == 0
    ent = plistlib.loads((root / 'entitlements').read_bytes())
    assert ent == {'com.apple.application-identifier': 'TEAM.net.test.mop',
                   'com.apple.developer.team-identifier': 'TEAM',
                   'keychain-access-groups': ['TEAM.net.test.mop']}
    assert plistlib.loads((root / 'info').read_bytes())['CFBundleExecutable'] == 'mop'
    for field, value in [('com.apple.application-identifier', 'TEAM.*'),
                         ('com.apple.application-identifier', 'TEAM.net.other.app'),
                         ('com.apple.developer.team-identifier', ''),
                         ('keychain-access-groups', ['TEAM.net.other.app'])]:
        bad = copy.deepcopy(base)
        bad['Entitlements'][field] = value
        assert generate(bad).returncode != 0, field
    expired = copy.deepcopy(base)
    expired['ExpirationDate'] = datetime.datetime.now() - datetime.timedelta(days=1)
    assert generate(expired).returncode != 0
print('PASS: explicit identity, narrow access group, no debug entitlements, and profile rejection checks.')
