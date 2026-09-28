#!/usr/bin/env python3
"""Check resources without authentication: BINARY [HOMEBREW_KEG_PREFIX]."""
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'dist/2ndPass.app/Contents/MacOS/2ndpass').resolve()
brew_prefix = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
share = brew_prefix / 'share' if brew_prefix else (binary.parents[3] / 'share' if binary.parent.name == 'MacOS' else binary.parent / 'share')
bash_script = (brew_prefix / 'etc/bash_completion.d/2ndpass' if brew_prefix
               else share / 'bash-completion/completions/2ndpass')
scripts = {'bash': bash_script,
           'zsh': share / 'zsh/site-functions/_2ndpass',
           'fish': share / 'fish/vendor_completions.d/2ndpass.fish'}
env = os.environ | {'MOP_CLOUD_VAULT': '00000000-0000-0000-0000-000000000000',
                    'MOP_STATE_DIRECTORY': '/nonexistent/2ndpass-completion-state'}
for shell, path in scripts.items():
    generated = subprocess.check_output([str(binary), 'completion', shell], env=env)
    assert generated == path.read_bytes()
    assert b'rename' in generated and b'fingerprint' in generated and b'no-masking' in generated and b'strict-biometrics' not in generated
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
_2ndpass 2ndpass "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
printf '%s\\n' "${COMPREPLY[@]}"
'''
    result = subprocess.run(['/bin/bash', '-c', code, 'test', str(scripts['bash']), *words],
                            cwd=cwd, env=env, text=True, capture_output=True, check=True)
    assert not result.stderr, result.stderr
    return result.stdout.splitlines()

assert 'read' in bash_candidates(['2ndpass', 're'])
assert 'enrollment' in bash_candidates(['2ndpass', 'vault', 'en'])
assert 'rename' in bash_candidates(['2ndpass', 'vault', 'ren'])
assert 'delete' in bash_candidates(['2ndpass', 'vault', 'del'])
assert '--confirm' in bash_candidates(['2ndpass', 'vault', 'delete', '--con'])
assert '--strict-biometrics' not in bash_candidates(['2ndpass', 'vault', 'init', '--strict'])
assert '--device-name' not in bash_candidates(['2ndpass', 'vault', 'init', '--device'])
assert '--no-masking' in bash_candidates(['2ndpass', 'run', '--no'])
assert set(bash_candidates(['2ndpass', 'completion', ''])) == {'bash', 'zsh', 'fish'}
with tempfile.TemporaryDirectory(prefix='2ndpass-completion-test-') as directory:
    root = Path(directory)
    (root / 'input file.env').write_text('literal')
    (root / 'input directory').mkdir()
    assert 'input file.env' in bash_candidates(['2ndpass', 'run', '--env-file', 'input'], cwd=root)
    directories = bash_candidates(['2ndpass', 'read', '--state-directory', 'input'], cwd=root)
    assert 'input directory' in directories and 'input file.env' not in directories
    # Register zsh's autoload completion without writing a completion cache.
    subprocess.run(['/bin/zsh', '-f', '-c',
                    'fpath=("$1" $fpath); autoload -Uz compinit; compinit -D; [[ ${_comps[2ndpass]} == _2ndpass ]]',
                    'test', str(scripts['zsh'].parent)], check=True, env=env, cwd=root)

fish = shutil.which('fish')
if fish:
    result = subprocess.check_output([fish, '-c', 'source $argv[1]; complete -C "2ndpass completion "', str(scripts['fish'])], env=env, text=True)
    assert {'bash', 'zsh', 'fish'} <= {line.split('\t')[0] for line in result.splitlines()}

manual = share / 'man/man1/2ndpass.1'
result = subprocess.run(['mandoc', '-Tascii', str(manual)], check=True, capture_output=True)
rendered = re.sub(rb'.\x08', b'', result.stdout)
assert b'2NDPASS(1)' in rendered and b'SECURITY' in rendered
assert manual.read_bytes() == (Path(__file__).resolve().parent.parent / 'docs/man/2ndpass.1').read_bytes()
print('PASS: packaged resources, Bash candidates and paths, zsh registration, and manpage rendering.')
