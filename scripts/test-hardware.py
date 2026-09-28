#!/usr/bin/env python3
"""Opt-in live v7 device-identity checks. Requires interactive authentication approvals.
Creates a disposable CloudKit vault; retains local state and encrypted checkpoints.
Uses or creates a device-local hardware identity; optionally accepts a separate recovery device request.
See docs/VALIDATION.md. Never reads an existing vault.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('cli', nargs='?', default='dist/2ndPass.app/Contents/MacOS/2ndpass')
parser.add_argument('--recovery-request', type=Path)
parser.add_argument('--fingerprint', help='Independently verified recovery request fingerprint')
options = parser.parse_args()
if (options.recovery_request is None) != (options.fingerprint is None):
    parser.error("Supply both --recovery-request and --fingerprint, or neither.")
cli = str(Path(options.cli).resolve())
if subprocess.check_output([cli, '--version'], text=True).strip() != '0.7.0':
    raise SystemExit('This check requires the v7 (0.7.0) executable; no old-format probe will run.')
if os.environ.get('MOP_LIVE_CLOUD_TEST') != '1':
    raise SystemExit('Set MOP_LIVE_CLOUD_TEST=1 to create a disposable vault in the signed build CloudKit environment.')
# Retain recovery material and state until the operator deletes the remote test zone.
directory = tempfile.mkdtemp(prefix='2ndpass-cloud-hardware-v7-')
root = Path(directory)
vault_id = str(uuid.uuid4())
environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
               'MOP_STATE_DIRECTORY': str(root / 'state')}
print(f'Disposable cloud vault: {vault_id}; retained local fixtures: {root}', flush=True)
first = b'disposable-multiline-value\nsecond line'
second = b'disposable-other-token'
vault_name = 'test-' + vault_id
ref_a = f'secondpass://{vault_name}/service/api/token'
ref_b = f'secondpass://{vault_name}/service/password'

def command(label, args, data=b'', extra=None, code=0):
    print(label + ': authenticate when prompted.', flush=True)
    try:
        routed = list(args)
        position = routed.index('--') if '--' in routed else len(routed)
        routed[position:position] = ['--vault', vault_id]
        result = subprocess.run([cli, *routed], input=data, capture_output=True,
                                env=environment | (extra or {}), timeout=120)
    except subprocess.TimeoutExpired:
        raise SystemExit(f'{label}: authentication/command timed out; local fixtures are retained for recovery.')
    if result.returncode != code:
        raise SystemExit(f'{label} failed with code {result.returncode}; expected {code}')
    return result

initialization = ['vault', 'init', vault_name]
if options.recovery_request is not None:
    initialization += ['--recovery-request', str(options.recovery_request.resolve()), '--fingerprint', options.fingerprint]
command('Initialize disposable vault', initialization)
command('Write sectioned multiline field', ['write', ref_a], first)
command('Write second field', ['write', ref_b], second)
# Hash assertions verify delivery without placing secret values in argv.
child = ("import os,hashlib; "
         f"assert hashlib.sha256(os.environ['A'].encode()).hexdigest() == '{hashlib.sha256(first).hexdigest()}'; "
         "assert os.environ['A']==os.environ['REPEAT']; "
         f"assert hashlib.sha256(os.environ['B'].encode()).hexdigest() == '{hashlib.sha256(second).hexdigest()}'; "
         "os.write(1,os.environ['A'].encode()); os.write(2,os.environ['B'].encode())")
result = command('Run with two fields and a repeated reference', ['run', '--', sys.executable, '-c', child],
                 extra={'A': 'secondpass://$VAULT/service/api/token', 'REPEAT': ref_a, 'B': ref_b, 'VAULT': vault_name})
assert result.stdout == b'[concealed by 2ndpass]' and result.stderr == b'[concealed by 2ndpass]', 'Masking failed'
template = ('{{' + ref_a + '}}|{{secondpass://' + vault_name + '/service/${FIELD}}}|{{' + ref_a + '}}').encode()
output = root / 'config'
result = command('Inject atomically with expanded references', ['inject', '-o', str(output)], template,
                 extra={'FIELD': 'password'})
assert result.stdout == b'', 'File output unexpectedly wrote to stdout'
expected = first + b'|' + second + b'|' + first
assert output.read_bytes() == expected, 'Template resolution failed'
assert output.stat().st_mode & 0o777 == 0o600, 'Output permissions incorrect'
read_file = root / 'read'
command('Read multiline field without appended newline', ['read', ref_a, '-n', '-o', str(read_file)])
assert read_file.read_bytes() == first, 'Read output differed'
result = command('Reject partial template output for a missing field', ['inject', '-o', str(output), '-f'],
                 ('{{' + ref_a + '}}{{secondpass://' + vault_name + '/missing/field}}').encode(), code=4)
assert result.stdout == b'' and output.read_bytes() == expected, 'Failed lookup altered output'
print('PASS: release hardware CRUD, sections, expansion, masking, repeated references, atomic output, and failure without partial output.', flush=True)
