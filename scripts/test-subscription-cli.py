#!/usr/bin/env python3
"""Reporting smoke tests against an unsigned build; no vault/cloud access required."""
import json
import subprocess
import sys

binary = sys.argv[1] if len(sys.argv) > 1 else '.build/out/Products/Release/sp'
def run(*args):
    return subprocess.run([binary, *args], capture_output=True, text=True, timeout=5)

for args in [('--help',), ('--version',), ('subscription', '--help'),
             ('subscription', 'status', '--help'), ('vault', 'recover', '--help'),
             ('help', 'read'), ('--generate-completion-script', 'bash'),
             ('completion', 'bash'), ('completion', 'zsh'), ('completion', 'fish')]:
    result = run(*args)
    assert result.returncode == 0, (args, result.stderr)
    assert result.stdout and not result.stderr, (args, result.stderr)
for args in [('subscription', 'status', '--json', '--offline'), ('subscription', 'status', '--json')]:
    result = run(*args)
    assert result.returncode == 0 and not result.stderr, result
    status = json.loads(result.stdout)
    assert status['status'] == 'unavailable' and status['source'] == 'none', status
    assert 'expiration' in status and status['expiration'] is None
    assert 'lastVerified' in status and status['lastVerified'] is None
result = run('--unknown-option')
assert result.returncode != 0 and not result.stdout
assert 'reporting only' not in result.stderr
result = run('read', 'invalid-reference', '--offline')
assert result.returncode != 0 and not result.stdout
assert result.stderr.count('reporting only') == 1, result.stderr
print('PASS: help, version, completions, recovery help, JSON, offline, and error output contracts')
