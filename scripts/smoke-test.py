#!/usr/bin/env python3
"""Exercise the CLI without authentication or creating a vault."""
import json
import os
import pathlib
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import uuid

mop = str(pathlib.Path(sys.argv[1]).resolve())
environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
               "MOP_CLOUD_VAULT": str(uuid.uuid4())}
checks = 0


def run(args, *, data=b"", code=0, output=None, env=None):
    global checks
    result = subprocess.run([mop, *args], input=data, capture_output=True,
                            env=environment | (env or {}), timeout=15)
    assert result.returncode == code, (args, result.returncode, result.stderr)
    if output is not None:
        assert result.stdout == output, (args, result.stdout, output)
    checks += 1
    return result


run(["--help"])
run(["--version"], output=b"0.4.0\n")
for shell in ('bash', 'zsh', 'fish'):
    script = run(['completion', shell]).stdout
    assert script and script == run(['--generate-completion-script', shell]).stdout
run(['completion'], code=2, output=b'')
run(['completion', 'unsupported'], code=2, output=b'')
for command in ("read", "write", "list", "delete", "run", "inject", "vault", "device", "completion"):
    run([command, "--help"])
run(["vault", "trust", "--help"])
run(["vault", "fingerprint", "--help"])
run(["vault", "trust"], code=2, output=b"")
run(["vault", "trust", "--fingerprint", "invalid"], code=2, output=b"")
run(["vault", "trust", "--fingerprint", "0" * 64, "--revision", "0" * 64], code=2, output=b"")
run(["vault", "recover", "--recovery-file", "/unused", "--fingerprint", "invalid"], code=2, output=b"")
run(["read", "mop://v/i/f", "--vault-file", "/unused"], code=2, output=b"")
run(["read", "mop://v/i/f"], env={"MOP_VAULT_FILE": "/unused"}, code=2, output=b"")
run(["write", "mop://v/i/f", "--offline"], code=2, output=b"")
run(["delete", "mop://v/i/f", "--offline"], code=2, output=b"")
for command in ("list", "use", "sync", "status", "import", "export"):
    run(["vault", command, "--help"])
run(["read", "invalid"], code=2, output=b"")
run(["read"], code=2, output=b"")
run(["unknown"], code=2, output=b"")
result = run(["write", "mop://test/item/field", "accidental-secret-argument"], code=2, output=b"")
assert b"accidental-secret-argument" not in result.stderr
run(["read", "mop://test/item/field"], code=8, output=b"")
run(["list", "--json"], code=8, output=b"")
run(["delete", "mop://test/item/field"], code=8, output=b"")
run(["write", "mop://test/item/field"], data=b"disposable\n", code=8, output=b"")
run(["write", "mop://test/item/field"], data=b"\xff", code=7, output=b"")
run(["inject"], data="literal ✓ {{ other }}".encode(), output="literal ✓ {{ other }}".encode())
run(["inject"], data=b"prefix {{mop://test/item/field}}", code=8, output=b"")
run(["inject"], data=b"prefix {{mop://test/item/field", code=2, output=b"")
run(["inject"], data=b"\xff", code=7, output=b"")
run(["run"], code=2, output=b"")
run(["run", "--", "/usr/bin/printf", "%s", "--literal argument"], output=b"--literal argument")
run(["run", "--", "/bin/cat"], data=b"stdin\n", output=b"stdin\n")
run(["run", "--", "/bin/sh", "-c", "exit 42"], code=42, output=b"")
run(["run", "--", "/bin/sh", "-c", "kill -TERM $$"], code=-signal.SIGTERM, output=b"")
run(["run", "--", "mop-definitely-does-not-exist"], code=127, output=b"")
run(["run", "--", "printf", "%s", "path lookup"], output=b"path lookup")

with tempfile.TemporaryDirectory(prefix="mop-smoke-") as directory:
    root = pathlib.Path(directory)
    base = root / "base.env"
    override = root / "override.env"
    base.write_text("A=base\nB='literal ${A} $(false)'\n")
    override.write_text("A=override\n")
    result = run(["run", "--env-file", str(base), "--env-file", str(override), "--",
                  sys.executable, "-c", "import os,json; print(json.dumps([os.environ['A'],os.environ['B']]))"],
                 env={"A": "inherited"})
    assert json.loads(result.stdout) == ["override", "literal ${A} $(false)"]
    bad = root / "bad.env"
    bad.write_text("TOKEN='disposable-value-must-not-leak\n")
    result = run(["run", "--env-file", str(bad), "--", "/bin/true"], code=2, output=b"")
    assert b"disposable-value-must-not-leak" not in result.stderr
    marker = root / "must-not-exist"
    run(["run", "--", "/usr/bin/touch", str(marker)],
        env={"TOKEN": "mop://test/item/field"}, code=8, output=b"")
    assert not marker.exists()
    script = root / "no-shebang"
    script.write_text("touch " + str(marker) + "\n")
    script.chmod(0o700)
    run(["run", "--", str(script)], code=126, output=b"")
    assert not marker.exists()
    script.chmod(0o600)
    run(["run", "--", str(script)], code=126, output=b"")
    template = root / "template"
    template.write_text("from file\n")
    run(["inject", "--in-file", str(template)], output=b"from file\n")
    run(["inject", "--in-file", str(root / "missing")], code=7, output=b"")

# New compatibility options fail before authentication and never truncate output.
for args in (["read", "mop://v/i/f", "--force"], ["inject", "--file-mode", "0600"],
             ["inject", "--out-file", "/tmp/unused-mop-output", "--file-mode", "4755"]):
    run(args, code=2, output=b"")
run(["inject"], data=b"{{mop://v/i/${MISSING}}}", code=2, output=b"")
run(["inject"], data=b"{{mop://v/i/${FIELD}}}", env={"FIELD": "token"}, code=8, output=b"")
run(["run", "--", "/bin/true"], env={"TOKEN": "mop://$MISSING/i/f"}, code=2, output=b"")
for extra in ([], ["--no-masking"]):
    run(["run", *extra, "--", "/bin/cat"], data=b"direct input", output=b"direct input")
    run(["run", *extra, "--", "/bin/sh", "-c", "exit 23"], code=23, output=b"")

with tempfile.TemporaryDirectory(prefix="mop-output-smoke-") as directory:
    root = pathlib.Path(directory)
    destination = root / "output"
    run(["inject", "-o", str(destination)], data=b"first", output=b"")
    assert destination.read_bytes() == b"first"
    assert destination.stat().st_mode & 0o777 == 0o600
    result = run(["inject", "-o", str(destination)], data=b"bad", code=5, output=b"")
    assert b"--force" in result.stderr
    run(["inject", "-o", str(destination), "-f", "--file-mode", "0640"], data=b"second", output=b"")
    assert destination.read_bytes() == b"second"
    assert destination.stat().st_mode & 0o777 == 0o640
    run(["inject", "-i", str(destination), "-o", str(destination), "-f"], output=b"")
    assert destination.read_bytes() == b"second"
    run(["inject", "-o", str(destination), "-f"], data=b"{{mop://v/i/f}}", code=8, output=b"")
    assert destination.read_bytes() == b"second"
    run(["read", "mop://v/i/f", "-n", "-o", str(destination), "-f"], code=8, output=b"")
    assert destination.read_bytes() == b"second"
    missing = root / "never-created"
    run(["inject", "-o", str(missing)], data=b"{{mop://v/i/f}}", code=8, output=b"")
    assert not missing.exists()
    alias = root / "alias"
    alias.symlink_to(destination)
    run(["inject", "-o", str(alias), "-f"], data=b"bad", code=15, output=b"")
    run(["inject", "--vault-file", str(destination), "-o", str(destination), "-f"], data=b"bad", code=2, output=b"")
    history = root / "vault.history"
    history.mkdir()
    run(["inject", "--state-directory", str(root / "vault"), "-o", str(root / "vault" / "revision")], data=b"bad", code=15, output=b"")
    state = root / "state"
    state.mkdir()
    run(["inject", "--state-directory", str(state), "-o", str(state / "device.json")], data=b"bad", code=15, output=b"")
    run(["inject", "--state-directory", str(state), "-o", str(state / "trust/pin.json")], data=b"bad", code=15, output=b"")
    assert destination.read_bytes() == b"second"
    assert not list(root.glob(".mop-output-*"))

# A signal sent to the supervisor must reach the child, whose exit status wins.
child_code = "import signal,time; signal.signal(signal.SIGTERM,lambda *args: exit(23)); print('ready',flush=True); time.sleep(30)"
child = subprocess.Popen([mop, "run", "--", sys.executable, "-c", child_code],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
try:
    assert select.select([child.stdout], [], [], 10)[0], "Child did not become ready"
    assert child.stdout.readline() == b"ready\n"
    child.send_signal(signal.SIGTERM)
    stdout, stderr = child.communicate(timeout=10)
    assert child.returncode == 23, (child.returncode, stderr)
    checks += 1
finally:
    if child.poll() is None:
        child.kill()
        child.communicate()

# --no-masking retains terminal descriptors, while masked stdout is a pipe.
for extra, expected in (([], b"True False"), (["--no-masking"], b"True True")):
    master, slave = pty.openpty()
    child = subprocess.Popen([mop, "run", *extra, "--", sys.executable, "-c",
                              "import os; print(os.isatty(0),os.isatty(1))"],
                             stdin=slave, stdout=slave, stderr=subprocess.PIPE, env=environment)
    try:
        assert select.select([master], [], [], 10)[0], "Terminal check timed out"
        observed = os.read(master, 4096).strip()
        _, stderr = child.communicate(timeout=10)
        assert child.returncode == 0 and observed == expected, (observed, stderr)
        checks += 1
    finally:
        os.close(master)
        os.close(slave)
        if child.poll() is None:
            child.kill()
            child.communicate()

# Verify hidden input and echo restoration on a controlling terminal.
pid, terminal = pty.fork()
if pid == 0:
    os.execve(mop, [mop, "write", "mop://test/item/field"], environment)
transcript = b""
status = None
try:
    deadline = time.monotonic() + 10
    while b"Secret: " not in transcript and time.monotonic() < deadline:
        if select.select([terminal], [], [], 0.2)[0]:
            transcript += os.read(terminal, 4096)
    assert b"Secret: " in transcript, transcript
    assert not (termios.tcgetattr(terminal)[3] & termios.ECHO)
    os.write(terminal, b"disposable-hidden-input\n")
    # Drain output while waiting: readpassphrase uses tcsetattr(TCSAFLUSH),
    # which can wait for the pseudo-terminal master to consume its newline.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if select.select([terminal], [], [], 0.1)[0]:
            try:
                transcript += os.read(terminal, 4096)
            except OSError:
                pass
        finished, candidate = os.waitpid(pid, os.WNOHANG)
        if finished:
            status = candidate
            break
    assert status is not None, "Hidden-input child timed out"
    assert os.waitstatus_to_exitcode(status) == 8, transcript
    assert b"disposable-hidden-input" not in transcript
    assert termios.tcgetattr(terminal)[3] & termios.ECHO
    checks += 1
finally:
    os.close(terminal)
    if status is None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

print(f"PASS: {checks} CLI smoke checks (no vaults or keys created).")
