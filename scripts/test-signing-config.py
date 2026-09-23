#!/usr/bin/env python3
"""Validate signing configuration generation without identities or Keychain access."""
import copy
import datetime
from pathlib import Path
import plistlib
import os
import subprocess
import sys
import tempfile

script = Path(__file__).with_name('signing-config.py')
base = {'ExpirationDate': datetime.datetime.now() + datetime.timedelta(days=1),
        'Entitlements': {'com.apple.application-identifier': 'TEAM.net.test.mop',
                         'com.apple.developer.team-identifier': 'TEAM',
                         'keychain-access-groups': ['TEAM.*'], 'get-task-allow': True,
                         'com.apple.developer.icloud-container-identifiers': ['iCloud.net.test.mop'],
                         'com.apple.developer.icloud-services': ['CloudKit'],
                         'com.apple.developer.icloud-container-environment': 'Production'}}
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    def generate(profile, environment="Production"):
        (root / 'profile').write_bytes(plistlib.dumps(profile))
        return subprocess.run([sys.executable, str(script), str(root / 'profile'),
                               'net.test.mop', 'mop', str(root / 'info'), str(root / 'entitlements')],
                              capture_output=True, env={**os.environ, "MOP_CLOUD_ENVIRONMENT": environment})
    assert generate(base).returncode == 0
    ent = plistlib.loads((root / 'entitlements').read_bytes())
    assert ent == {'com.apple.application-identifier': 'TEAM.net.test.mop',
                   'com.apple.developer.team-identifier': 'TEAM',
                   'keychain-access-groups': ['TEAM.net.test.mop'],
                   'com.apple.developer.icloud-container-identifiers': ['iCloud.net.test.mop'],
                   'com.apple.developer.icloud-services': ['CloudKit'],
                   'com.apple.developer.icloud-container-environment': 'Production'}
    assert plistlib.loads((root / 'info').read_bytes())['CFBundleExecutable'] == 'mop'
    for field, value in [('com.apple.application-identifier', 'TEAM.*'),
                         ('com.apple.application-identifier', 'TEAM.net.other.app'),
                         ('com.apple.developer.team-identifier', ''),
                         ('keychain-access-groups', ['TEAM.net.other.app']),
                         ('com.apple.developer.icloud-container-identifiers', ['iCloud.other']),
                         ('com.apple.developer.icloud-services', []),
                         ('com.apple.developer.icloud-container-environment', 'Development')]:
        bad = copy.deepcopy(base)
        bad['Entitlements'][field] = value
        assert generate(bad).returncode != 0, field
    # Apple profiles use allowed-value arrays and may authorize wildcard services.
    multiple = copy.deepcopy(base)
    multiple['Entitlements']['com.apple.developer.icloud-container-environment'] = ['Development', 'Production']
    multiple['Entitlements']['com.apple.developer.icloud-services'] = '*'
    multiple['Entitlements']['com.apple.developer.icloud-container-identifiers'] = ['iCloud.net.test.*']
    for environment in ('Development', 'Production'):
        assert generate(multiple, environment).returncode == 0
        narrowed = plistlib.loads((root / 'entitlements').read_bytes())
        assert narrowed['com.apple.developer.icloud-container-environment'] == environment
        assert narrowed['com.apple.developer.icloud-services'] == ['CloudKit']
        assert narrowed['com.apple.developer.icloud-container-identifiers'] == ['iCloud.net.test.mop']
    multiple['Entitlements']['com.apple.developer.icloud-container-environment'] = ['Development']
    result = generate(multiple)
    assert result.returncode != 0 and b'requires Production; profile permits Development' in result.stderr
    assert generate(multiple, 'Development').returncode == 0
    missing = copy.deepcopy(base)
    for key in list(missing['Entitlements']):
        if key.startswith('com.apple.developer.icloud-'):
            del missing['Entitlements'][key]
    result = generate(missing)
    assert result.returncode != 0
    assert b'requires iCloud.net.test.mop; profile permits (missing)' in result.stderr
    assert b'requires CloudKit; profile permits (missing)' in result.stderr
    assert b'regenerate/download' in result.stderr
    assert generate(base, 'invalid').returncode != 0
    expired = copy.deepcopy(base)
    expired['ExpirationDate'] = datetime.datetime.now() - datetime.timedelta(days=1)
    assert generate(expired).returncode != 0
print('PASS: explicit identity, narrow access group, no debug entitlements, and profile rejection checks.')
