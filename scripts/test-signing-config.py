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
        'Entitlements': {'com.apple.application-identifier': 'TEAM.net.test.mop.CLI',
                         'com.apple.developer.team-identifier': 'TEAM',
                         'com.apple.security.application-groups': ['group.net.test.mop'],
                         'keychain-access-groups': ['TEAM.*'], 'get-task-allow': True,
                         'com.apple.developer.icloud-container-identifiers': ['iCloud.net.test.mop'],
                         'com.apple.developer.icloud-services': ['CloudKit'],
                         'com.apple.developer.ubiquity-kvstore-identifier': 'TEAM.net.test.mop',
                         'com.apple.developer.icloud-container-environment': 'Production'}}
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    def generate(profile, environment="Production"):
        (root / 'profile').write_bytes(plistlib.dumps(profile))
        return subprocess.run([sys.executable, str(script), str(root / 'profile'),
                               'net.test.mop.CLI', 'sp', str(root / 'info'), str(root / 'entitlements')],
                              capture_output=True, env={**os.environ, "MOP_CLOUD_ENVIRONMENT": environment})
    assert generate(base).returncode == 0
    ent = plistlib.loads((root / 'entitlements').read_bytes())
    assert ent == {'com.apple.application-identifier': 'TEAM.net.test.mop.CLI',
                   'com.apple.developer.team-identifier': 'TEAM',
                   'keychain-access-groups': ['TEAM.net.test.mop'],
                   'com.apple.security.application-groups': ['group.net.test.mop'],
                   'com.apple.developer.icloud-container-identifiers': ['iCloud.net.test.mop'],
                   'com.apple.developer.icloud-services': ['CloudKit'],
                         'com.apple.developer.ubiquity-kvstore-identifier': 'TEAM.net.test.mop',
                   'com.apple.developer.icloud-container-environment': 'Production'}
    assert plistlib.loads((root / 'info').read_bytes())['CFBundleExecutable'] == 'sp'
    for field, value in [('com.apple.application-identifier', 'TEAM.*'),
                         ('com.apple.application-identifier', 'TEAM.net.other.app'),
                         ('com.apple.developer.team-identifier', ''),
                         ('keychain-access-groups', ['TEAM.net.other.app']),
                         ('com.apple.developer.icloud-container-identifiers', ['iCloud.other']),
                         ('com.apple.developer.icloud-services', []),
                         ('com.apple.developer.ubiquity-kvstore-identifier', 'TEAM.other'),
                         ('com.apple.developer.icloud-container-environment', 'Development')]:
        bad = copy.deepcopy(base)
        bad['Entitlements'][field] = value
        assert generate(bad).returncode != 0, field
    assert 'com.apple.security.app-sandbox' not in ent
    assert 'com.apple.developer.authentication-services.autofill-credential-provider' not in ent
    assert plistlib.loads((root / 'info').read_bytes())['MopPublishesAutoFill'] is False
    for field, value in [('keychain-access-groups', ['TEAM.net.test.mop.CLI']),
                         ('com.apple.security.application-groups', ['group.net.test.mop.CLI'])]:
        bad = copy.deepcopy(base)
        bad['Entitlements'][field] = value
        assert generate(bad).returncode != 0, field
    # Subscription publication cannot be enabled without a real App Store identifier.
    with __import__('unittest.mock', fromlist=['patch']).patch.dict(os.environ, {'MOP_SUBSCRIPTION_PUBLICATION': 'YES', 'MOP_APP_APPLE_ID': ''}):
        assert generate(base).returncode != 0
    with __import__('unittest.mock', fromlist=['patch']).patch.dict(os.environ, {'MOP_SUBSCRIPTION_PUBLICATION': 'YES', 'MOP_APP_APPLE_ID': '123456789'}):
        assert generate(base).returncode == 0
        info = plistlib.loads((root / 'info').read_bytes())
        assert info['MopAppAppleID'] == '123456789'
        assert info['MopSubscriptionPublicationEnabled'] == 'YES'
        assert info['MopSubscriptionPurchasesEnabled'] == 'NO'
    # Apple profiles use allowed-value arrays and may authorize wildcard services.
    multiple = copy.deepcopy(base)
    multiple['Entitlements']['com.apple.developer.icloud-container-environment'] = ['Development', 'Production']
    multiple['Entitlements']['com.apple.developer.icloud-services'] = '*'
    multiple['Entitlements']['com.apple.developer.ubiquity-kvstore-identifier'] = 'TEAM.*'
    multiple['Entitlements']['com.apple.developer.icloud-container-identifiers'] = ['iCloud.net.test.*']
    for environment in ('Development', 'Production'):
        assert generate(multiple, environment).returncode == 0
        narrowed = plistlib.loads((root / 'entitlements').read_bytes())
        assert narrowed['com.apple.developer.icloud-container-environment'] == environment
        assert narrowed['com.apple.developer.icloud-services'] == ['CloudKit']
        assert narrowed['com.apple.developer.ubiquity-kvstore-identifier'] == 'TEAM.net.test.mop'
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
    # AutoFill requires both capabilities; the extension retains the app's group.
    autofill = copy.deepcopy(base)
    autofill['Entitlements'].update({
        'com.apple.application-identifier': 'TEAM.net.test.mop.AutoFill',
        'keychain-access-groups': ['TEAM.net.test.mop'],
        'com.apple.developer.authentication-services.autofill-credential-provider': True,
        'com.apple.security.application-groups': ['group.net.test.mop']})
    def extension(profile):
        (root / 'profile').write_bytes(plistlib.dumps(profile))
        return subprocess.run([sys.executable, str(script), str(root / 'profile'),
                               'net.test.mop.AutoFill', 'MopAutoFill', str(root / 'info'), str(root / 'entitlements')],
                              capture_output=True, env={**os.environ, "MOP_CLOUD_ENVIRONMENT": "Production"})
    wrong_app = extension(base)
    assert wrong_app.returncode != 0
    assert b'TEAM.net.test.mop' in wrong_app.stderr
    assert b'net.test.mop.AutoFill' in wrong_app.stderr
    assert b'MOP_AUTOFILL_PROVISION_PROFILE' in wrong_app.stderr
    result = extension(autofill)
    assert result.returncode == 0, result.stderr
    extension_ent = plistlib.loads((root / 'entitlements').read_bytes())
    assert extension_ent['keychain-access-groups'] == ['TEAM.net.test.mop']
    assert extension_ent['com.apple.developer.icloud-container-identifiers'] == ['iCloud.net.test.mop']
    assert extension_ent['com.apple.security.app-sandbox'] is True
    for key in ['com.apple.security.application-groups', 'com.apple.developer.authentication-services.autofill-credential-provider']:
        bad = copy.deepcopy(autofill)
        del bad['Entitlements'][key]
        assert extension(bad).returncode != 0
    host = copy.deepcopy(base)
    host['Entitlements']['com.apple.application-identifier'] = 'TEAM.net.test.mop'
    host['Entitlements']['com.apple.developer.authentication-services.autofill-credential-provider'] = True
    (root / 'profile').write_bytes(plistlib.dumps(host))
    result = subprocess.run([sys.executable, str(script), str(root / 'profile'),
                             'net.test.mop', 'MopApp', str(root / 'info'), str(root / 'entitlements')], capture_output=True)
    assert result.returncode == 0, result.stderr
    host_ent = plistlib.loads((root / 'entitlements').read_bytes())
    for key in ('com.apple.security.app-sandbox', 'com.apple.security.network.client',
                'com.apple.security.files.user-selected.read-write'):
        assert host_ent[key] is True
    assert host_ent['keychain-access-groups'] == ent['keychain-access-groups']
    assert plistlib.loads((root / 'info').read_bytes())['MopPublishesAutoFill'] is True
print('PASS: explicit identity, narrow access group, no debug entitlements, and profile rejection checks.')
