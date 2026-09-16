#!/usr/bin/env python3
"""Check packaged manpage/completions without opening a vault or authenticating."""
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'dist/mop').resolve()
share = binary.parent / 'share'
scripts = {'bash': share / 'bash-completion/completions/mop',
           'zsh': share / 'zsh/site-functions/_mop',
           'fish': share / 'fish/vendor_completions.d/mop.fish'}
env = os.environ | {'MOP_VAULT_FILE': '/nonexistent/mop-completion-test',
                    'MOP_STATE_DIRECTORY': '/nonexistent/mop-completion-state'}
for shell, path in scripts.items():
    generated = subprocess.check_output([str(binary), 'completion', shell], env=env)
    assert generated == path.read_bytes()
    assert b'vault-file' in generated and b'fingerprint' in generated and b'no-masking' in generated
    executable = shutil.which(shell)
    if executable:
        subprocess.run([executable, '-n', str(path)], check=True, env=env)
    else:
        print(f'NOTE: {shell} is unavailable; generated script checked, runtime validation skipped.')

# Ask the installed macOS Bash completion function for actual candidates.
def bash_candidates(words, cwd=None):
    code = '''source "$1"
shift
COMP_WORDS=("$@")
COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
COMP_LINE="${COMP_WORDS[*]}"
COMP_POINT=${#COMP_LINE}
COMPREPLY=()
_mop mop "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
printf '%s\\n' "${COMPREPLY[@]}"
'''
    result = subprocess.run(['/bin/bash', '-c', code, 'test', str(scripts['bash']), *words],
                            cwd=cwd, env=env, text=True, capture_output=True, check=True)
    assert not result.stderr, result.stderr
    return result.stdout.splitlines()

assert 'read' in bash_candidates(['mop', 're'])
assert 'trust' in bash_candidates(['mop', 'vault', 'tr'])
assert '--no-masking' in bash_candidates(['mop', 'run', '--no'])
assert set(bash_candidates(['mop', 'completion', ''])) == {'bash', 'zsh', 'fish'}
with tempfile.TemporaryDirectory(prefix='mop-completion-test-') as directory:
    root = Path(directory)
    (root / 'input file.env').write_text('literal')
    (root / 'input directory').mkdir()
    assert 'input file.env' in bash_candidates(['mop', 'run', '--env-file', 'input'], cwd=root)
    directories = bash_candidates(['mop', 'read', '--state-directory', 'input'], cwd=root)
    assert 'input directory' in directories and 'input file.env' not in directories
    # Register zsh's autoload completion without writing a completion cache.
    subprocess.run(['/bin/zsh', '-f', '-c',
                    'fpath=("$1" $fpath); autoload -Uz compinit; compinit -D; [[ ${_comps[mop]} == _mop ]]',
                    'test', str(scripts['zsh'].parent)], check=True, env=env, cwd=root)

fish = shutil.which('fish')
if fish:
    result = subprocess.check_output([fish, '-c', 'source $argv[1]; complete -C "mop completion "', str(scripts['fish'])], env=env, text=True)
    assert {'bash', 'zsh', 'fish'} <= {line.split('\t')[0] for line in result.splitlines()}

manual = share / 'man/man1/mop.1'
result = subprocess.run(['mandoc', '-Tascii', str(manual)], check=True, capture_output=True)
rendered = re.sub(rb'.\x08', b'', result.stdout)
assert b'MOP(1)' in rendered and b'EXIT STATUS' in rendered
assert manual.read_bytes() == (Path(__file__).resolve().parent.parent / 'docs/man/mop.1').read_bytes()
print('PASS: packaged resources, Bash candidates and paths, zsh registration, and manpage rendering.')
