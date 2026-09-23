#!/usr/bin/env python3
"""Validate a provisioning profile and emit least-privilege signing inputs."""
import datetime
import fnmatch
import os
import plistlib
import sys
from pathlib import Path

profile_path, bundle_id, executable, info_path, entitlements_path = sys.argv[1:]
with open(profile_path, 'rb') as f:
    profile = plistlib.load(f)
entitlements = profile['Entitlements']
app_id = entitlements.get('com.apple.application-identifier', '')
team = entitlements.get('com.apple.developer.team-identifier', '')
if not team or not app_id.endswith('.' + bundle_id) or '*' in app_id:
    sys.exit('Use an explicit macOS provisioning profile matching the bundle identifier.')
if profile.get('ExpirationDate', datetime.datetime.min) <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
    sys.exit('The provisioning profile has expired.')
if not any(fnmatch.fnmatchcase(app_id, group) for group in entitlements.get('keychain-access-groups', [])):
    sys.exit('The provisioning profile must permit the application-specific Keychain group.')
output = {'com.apple.application-identifier': app_id,
          'com.apple.developer.team-identifier': team,
          'keychain-access-groups': [app_id]}
if executable == 'mop':
    container = 'iCloud.' + bundle_id
    environment = os.environ.get('MOP_CLOUD_ENVIRONMENT', 'Production')
    if environment not in ('Development', 'Production'):
        sys.exit('MOP_CLOUD_ENVIRONMENT must be Development or Production.')
    # Profiles describe allowed values (often arrays or wildcards); the app's
    # signature must contain the single concrete environment/container we use.
    def allowed_values(key):
        value = entitlements.get(key)
        if isinstance(value, str):
            return [value]
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return value
        return []

    def permits(key, requested):
        return any(fnmatch.fnmatchcase(requested, pattern) for pattern in allowed_values(key))

    required = [('com.apple.developer.icloud-container-identifiers', container),
                ('com.apple.developer.icloud-services', 'CloudKit'),
                ('com.apple.developer.icloud-container-environment', environment)]
    problems = []
    for key, requested in required:
        if not permits(key, requested):
            permitted = ', '.join(allowed_values(key)) or '(missing)'
            problems.append(f'  {key}: requires {requested}; profile permits {permitted}')
    if problems:
        sys.exit('CloudKit provisioning does not authorize this build:\n' + '\n'.join(problems)
                 + f'\nEnable CloudKit for {bundle_id}, associate {container}, then regenerate/download its profile.'
                 + '\nMOP_CLOUD_ENVIRONMENT selects Development or Production (default Production); the profile must permit it.')
    output.update({'com.apple.developer.icloud-container-identifiers': [container],
                   'com.apple.developer.icloud-services': ['CloudKit'],
                   'com.apple.developer.icloud-container-environment': environment})
with open(entitlements_path, 'wb') as f:
    plistlib.dump(output, f)
with open(info_path, 'wb') as f:
    plistlib.dump({'CFBundleIdentifier': bundle_id, 'CFBundleExecutable': executable,
                  'CFBundleName': 'mop', 'CFBundlePackageType': 'APPL',
                  'CFBundleVersion': '0.4.0', 'CFBundleShortVersionString': '0.4.0',
                  'LSMinimumSystemVersion': '15.0'}, f)
