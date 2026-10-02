#!/usr/bin/env python3
"""Test installation layout with explicit signing stubs; never touch system paths.
Real signature/entitlement validation remains in test-tooling.py with a signed app.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="sp-install-layout-") as directory:
    temp = Path(directory)
    package = temp / "package"
    app = package / "2ndPass CLI.app"
    helper = app / "Contents/MacOS/sp"
    helper.parent.mkdir(parents=True)
    helper.write_text('#!/bin/sh\necho TEST.net.koehn.mop\n')
    helper.chmod(0o700)
    app.chmod(0o700)
    (app / "Contents/embedded.provisionprofile").write_text("fixture")
    (app / "valid-signature").touch()
    resources = ["man/man1/sp.1", "bash-completion/completions/sp",
                 "zsh/site-functions/_sp", "fish/vendor_completions.d/sp.fish"]
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
    prefix = temp / "prefix"
    applications = prefix / "lib/sp"
    env = os.environ | {"PATH": str(stubs) + ":" + os.environ["PATH"],
                        "MOP_APPLICATIONS_DIR": str(applications), "MOP_INSTALL_ROOT": str(prefix)}
    command = ["/bin/bash", str(root / "scripts/install-cli.sh"), str(app)]
    def run(extra=None):
        return subprocess.run(command, env=env | (extra or {}), capture_output=True, text=True)
    result = run()
    assert result.returncode == 0, result.stderr
    assert not result.stderr, result.stderr
    installed = applications / "2ndPass CLI.app"
    link = prefix / "bin/sp"
    assert link.readlink() == installed / "Contents/MacOS/sp"
    assert installed.stat().st_mode & 0o055 == 0o055
    assert (installed / "Contents/MacOS/sp").stat().st_mode & 0o055 == 0o055
    assert not (temp / "Applications/2ndPass.app").exists()
    for resource in resources:
        target = prefix / "share" / resource
        assert target.is_symlink() and target.read_text() == resource
    # An existing signed app may still contain the previous CLI filename.
    (installed / "Contents/MacOS/sp").rename(installed / "Contents/MacOS/2ndpass")
    result = run()
    assert result.returncode == 0, result.stderr
    assert not result.stderr, result.stderr
    assert (installed / "Contents/MacOS/sp").is_file()
    assert not (installed / "Contents/MacOS/2ndpass").exists()
    # Migrating the old GUI's link must never move or replace that GUI.
    gui = temp / "Applications/2ndPass.app"
    gui.mkdir(parents=True)
    (gui / "untouched").write_text("GUI")
    link.unlink()
    link.symlink_to("/Applications/2ndPass.app/Contents/MacOS/sp")
    assert run().returncode == 0
    assert (gui / "untouched").read_text() == "GUI"
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
    link.symlink_to(installed / "Contents/MacOS/sp")
    marker = installed / "valid-signature"
    marker.unlink()
    assert run().returncode != 0
    assert not marker.exists(), "unverified application must not be overwritten"
print("PASS: application/CLI layout, permissions, upgrades, rollback, and collision checks (signing stubbed).")
