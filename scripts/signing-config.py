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
    sys.exit(f'Provisioning profile {profile.get("Name", "(unnamed)")!r} authorizes {app_id or "(missing App ID)"}, '
             f'but this target requires <AppIdentifierPrefix>.{bundle_id}. '
             + ('Set MOP_AUTOFILL_PROVISION_PROFILE to a separate profile for the AutoFill extension.'
                if executable == 'MopAutoFill' else 'Set MOP_PROVISION_PROFILE to the matching app profile.'))
if profile.get('ExpirationDate', datetime.datetime.min) <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
    sys.exit('The provisioning profile has expired.')
if executable != 'MopAutoFill' and not any(fnmatch.fnmatchcase(app_id, group) for group in entitlements.get('keychain-access-groups', [])):
    sys.exit('The provisioning profile must permit the application-specific Keychain group.')
is_extension = executable == 'MopAutoFill'
parent_bundle = bundle_id.removesuffix('.AutoFill') if is_extension else bundle_id
shared_group = app_id.removesuffix('.AutoFill') if is_extension else app_id
if is_extension and not bundle_id.endswith('.AutoFill'):
    sys.exit('AutoFill extension bundle ID must end in .AutoFill.')
if not any(fnmatch.fnmatchcase(shared_group, group) for group in entitlements.get('keychain-access-groups', [])):
    sys.exit('The extension profile must authorize the containing app Keychain group.')
output = {'com.apple.application-identifier': app_id,
          'com.apple.developer.team-identifier': team,
          'keychain-access-groups': [shared_group]}
if executable == 'sp' or is_extension:
    container = 'iCloud.' + parent_bundle
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

    kvstore = team + '.' + parent_bundle
    required = [('com.apple.developer.ubiquity-kvstore-identifier', kvstore),
                ('com.apple.developer.icloud-container-identifiers', container),
                ('com.apple.developer.icloud-services', 'CloudKit'),
                ('com.apple.developer.icloud-container-environment', environment)]
    if is_extension:
        required = required[1:]
    problems = []
    for key, requested in required:
        if not permits(key, requested):
            permitted = ', '.join(allowed_values(key)) or '(missing)'
            problems.append(f'  {key}: requires {requested}; profile permits {permitted}')
    if problems:
        sys.exit('CloudKit provisioning does not authorize this build:\n' + '\n'.join(problems)
                 + f'\nEnable CloudKit and iCloud Key-Value Storage for {bundle_id}, associate {container}, then regenerate/download its profile.'
                 + '\nMOP_CLOUD_ENVIRONMENT selects Development or Production (default Production); the profile must permit it.')
    output.update({'com.apple.developer.ubiquity-kvstore-identifier': kvstore,
                   'com.apple.developer.icloud-container-identifiers': [container],
                   'com.apple.developer.icloud-services': ['CloudKit'],
                   'com.apple.developer.icloud-container-environment': environment})
autofill = is_extension or os.environ.get('MOP_AUTOFILL') == '1'
if autofill:
    capability = 'com.apple.developer.authentication-services.autofill-credential-provider'
    group = 'group.' + parent_bundle
    if entitlements.get(capability) is not True or not permits('com.apple.security.application-groups', group):
        sys.exit('Enable AutoFill Credential Provider and App Groups (' + group + ') and regenerate the provisioning profile.')
    output[capability] = True
    output['com.apple.security.application-groups'] = [group]
if is_extension:
    output.pop('com.apple.developer.ubiquity-kvstore-identifier', None)
    output['com.apple.security.app-sandbox'] = True
    output['com.apple.security.network.client'] = True
# Carry the profile's APNs environment into native macOS app signatures.
if executable == 'sp' and entitlements.get('com.apple.developer.aps-environment'):
    output['com.apple.developer.aps-environment'] = entitlements['com.apple.developer.aps-environment']
with open(entitlements_path, 'wb') as f:
    plistlib.dump(output, f)
with open(info_path, 'wb') as f:
    plistlib.dump({'CFBundleIdentifier': bundle_id, 'CFBundleExecutable': executable,
                  'CFBundleName': '2ndPass', 'CFBundleDisplayName': '2ndPass', 'CFBundlePackageType': 'APPL',
                  'CFBundleVersion': '0.7.0', 'CFBundleShortVersionString': '0.7.0',
                  'LSMinimumSystemVersion': '15.0'}, f)

if autofill:
    with open(info_path, 'rb') as f:
        info = plistlib.load(f)
    info.update({'MopAppGroup': 'group.' + parent_bundle,
                 'MopPublishesAutoFill': not is_extension,
                 'MopCloudContainer': 'iCloud.' + parent_bundle,
                 'MopCloudEnvironment': environment,
                 'MopKeychainAccessGroup': shared_group})
    with open(info_path, 'wb') as f:
        plistlib.dump(info, f)
