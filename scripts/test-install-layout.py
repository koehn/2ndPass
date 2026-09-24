#!/usr/bin/env python3
"""Test installation layout with explicit signing stubs; never touch system paths.
Real signature/entitlement validation remains in test-tooling.py with a signed app.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="mop-install-layout-") as directory:
    temp = Path(directory)
    package = temp / "package"
    app = package / "Mop.app"
    helper = app / "Contents/MacOS/mop"
    helper.parent.mkdir(parents=True)
    helper.write_text('#!/bin/sh\necho TEST.net.koehn.mop\n')
    helper.chmod(0o700)
    app.chmod(0o700)
    (app / "Contents/embedded.provisionprofile").write_text("fixture")
    (app / "valid-signature").touch()
    resources = ["man/man1/mop.1", "bash-completion/completions/mop",
                 "zsh/site-functions/_mop", "fish/vendor_completions.d/mop.fish"]
    for resource in resources:
        path = package / "share" / resource
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(resource)
    stubs = temp / "stubs"
    stubs.mkdir()
    codesign = stubs / "codesign"
    codesign.write_text('''#!/bin/sh
[ -f "$3/valid-signature" ] || exit 8
if [ "${FAIL_INSTALLED:-}" = "$3" ] && [ ! -f "$3/old-version" ]; then exit 8; fi
''')
    codesign.chmod(0o755)
    applications, prefix = temp / "Applications", temp / "prefix"
    env = os.environ | {"PATH": str(stubs) + ":" + os.environ["PATH"],
                        "MOP_APPLICATIONS_DIR": str(applications), "MOP_INSTALL_ROOT": str(prefix)}
    command = ["/bin/bash", str(root / "scripts/install.sh"), str(app)]
    def run(extra=None):
        return subprocess.run(command, env=env | (extra or {}), capture_output=True, text=True)
    result = run()
    assert result.returncode == 0, result.stderr
    installed = applications / "Mop.app"
    link = prefix / "bin/mop"
    assert link.readlink() == installed / "Contents/MacOS/mop"
    assert installed.stat().st_mode & 0o055 == 0o055
    assert (installed / "Contents/MacOS/mop").stat().st_mode & 0o055 == 0o055
    assert not (prefix / "lib/mop/Mop.app").exists()
    for resource in resources:
        target = prefix / "share" / resource
        assert target.is_symlink() and target.read_text() == resource
    (installed / "old-version").touch()
    result = run({"FAIL_INSTALLED": str(installed)})
    assert result.returncode != 0
    assert (installed / "old-version").exists(), "failed validation must restore previous app"
    assert not list(applications.glob(".mop-install.*"))
    assert run().returncode == 0
    assert not (installed / "old-version").exists()
    link.unlink()
    link.write_text("unrelated executable")
    assert run().returncode == 7
    assert link.read_text() == "unrelated executable"
    link.unlink()
    link.symlink_to("/bin/echo")
    assert run().returncode == 7 and link.readlink() == Path("/bin/echo")
    link.unlink()
    link.symlink_to(installed / "Contents/MacOS/mop")
    marker = installed / "valid-signature"
    marker.unlink()
    assert run().returncode != 0
    assert not marker.exists(), "unverified application must not be overwritten"
print("PASS: application/CLI layout, permissions, upgrades, rollback, and collision checks (signing stubbed).")
