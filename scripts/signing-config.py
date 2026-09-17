#!/usr/bin/env python3
"""Validate a provisioning profile and emit least-privilege signing inputs."""
import datetime
import fnmatch
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
with open(entitlements_path, 'wb') as f:
    plistlib.dump({'com.apple.application-identifier': app_id,
                  'com.apple.developer.team-identifier': team,
                  'keychain-access-groups': [app_id]}, f)
with open(info_path, 'wb') as f:
    plistlib.dump({'CFBundleIdentifier': bundle_id, 'CFBundleExecutable': executable,
                  'CFBundleName': 'mop', 'CFBundlePackageType': 'APPL',
                  'CFBundleVersion': '0.3.0', 'CFBundleShortVersionString': '0.3.0',
                  'LSMinimumSystemVersion': '15.0'}, f)
