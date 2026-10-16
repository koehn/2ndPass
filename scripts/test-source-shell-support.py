#!/usr/bin/env python3
"""Run shell/help resource checks against a built CLI without installing it."""
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent.parent
binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="sp-shell-test-") as directory:
    prefix = Path(directory)
    for shell, relative in [("bash", "etc/bash_completion.d/sp"),
                            ("zsh", "share/zsh/site-functions/_sp"),
                            ("fish", "share/fish/vendor_completions.d/sp.fish")]:
        target = prefix / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output([str(binary), "completion", shell]))
    man = prefix / "share/man/man1/sp.1"
    man.parent.mkdir(parents=True)
    man.write_bytes((root / "docs/man/sp.1").read_bytes())
    subprocess.run([sys.executable, str(root / "scripts/test-shell-support.py"), str(binary), str(prefix)], check=True)
