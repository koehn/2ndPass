#!/usr/bin/env python3
"""Opt-in live Secure Enclave checks. Requires seven authentication approvals.
Creates only disposable fixtures; removes the vault, history, key blob, and
recovery file on completion or failure. Never reads a user's existing vault.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

mop = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'dist/mop').resolve())
with tempfile.TemporaryDirectory(prefix='mop-hardware-030-') as directory:
    root = Path(directory)
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                   'MOP_VAULT_FILE': str(root / '.mopfile'),
                   'MOP_STATE_DIRECTORY': str(root / 'state')}
    first = b'disposable-multiline-value\nsecond line'
    second = b'disposable-other-token'
    ref_a = 'mop://test/service/api/token'
    ref_b = 'mop://test/service/password'

    def command(label, args, data=b'', extra=None, code=0):
        print(label + ': authenticate when prompted.', flush=True)
        try:
            result = subprocess.run([mop, *args], input=data, capture_output=True,
                                    env=environment | (extra or {}), timeout=120)
        except subprocess.TimeoutExpired:
            raise SystemExit(f'{label}: authentication/command timed out; temporary fixtures will be removed.')
        if result.returncode != code:
            raise SystemExit(f'{label} failed with code {result.returncode}; expected {code}')
        return result

    command('Initialize disposable vault', ['vault', 'init', '--recovery-file', str(root / 'recovery.key'),
                                           '--name', 'Disposable mop 0.3.0 test'])
    command('Write sectioned multiline field', ['write', ref_a], first)
    command('Write second field', ['write', ref_b], second)
    # Hash assertions verify delivery without placing secret values in argv.
    child = ("import os,hashlib; "
             f"assert hashlib.sha256(os.environ['A'].encode()).hexdigest() == '{hashlib.sha256(first).hexdigest()}'; "
             "assert os.environ['A']==os.environ['REPEAT']; "
             f"assert hashlib.sha256(os.environ['B'].encode()).hexdigest() == '{hashlib.sha256(second).hexdigest()}'; "
             "os.write(1,os.environ['A'].encode()); os.write(2,os.environ['B'].encode())")
    result = command('Run with two fields and a repeated reference', ['run', '--', sys.executable, '-c', child],
                     extra={'A': 'mop://$VAULT/service/api/token', 'REPEAT': ref_a, 'B': ref_b, 'VAULT': 'test'})
    assert result.stdout == b'[concealed by mop]' and result.stderr == b'[concealed by mop]', 'Masking failed'
    template = ('{{' + ref_a + '}}|{{mop://test/service/${FIELD}}}|{{' + ref_a + '}}').encode()
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
                     ('{{' + ref_a + '}}{{mop://test/missing/field}}').encode(), code=4)
    assert result.stdout == b'' and output.read_bytes() == expected, 'Failed lookup altered output'
    print('PASS: release hardware CRUD, sections, expansion, masking, repeated references, atomic output, and failure without partial output.', flush=True)
