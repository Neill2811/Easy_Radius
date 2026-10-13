"""Live MS-CHAP check. Skipped unless FreeRADIUS can be started on this machine."""

import subprocess
from pathlib import Path

import pytest

_LIVE = r"""
import re
import socket
import subprocess
import time
from pathlib import Path

from easy_radius.perms import remember, write_text
from easy_radius.userhash import hash_user_password, nt_hash

users = Path("/etc/freeradius/3.0/mods-config/files/authorize")
identity = remember(users)
original = users.read_text(encoding="utf-8")
clients = Path("/etc/freeradius/3.0/clients.conf").read_text(encoding="utf-8")
match = re.search(r"(?m)^\s*client\s+localhost\s*\{", clients)
if not match:
    raise SystemExit("localhost client missing")
chunk = clients[match.end(): match.end() + clients[match.end():].find("\n}")]
secret_match = re.search(r'(?m)^\s*secret\s*=\s*"?(.*?)"?\s*$', chunk)
if not secret_match:
    raise SystemExit("localhost secret missing")
secret = secret_match.group(1).strip()

crypt = hash_user_password("example-password", salt="examplesalt1234")
nt = nt_hash("example-password")
extra = (
    f'\neasyhashcheck Crypt-Password := "{crypt}", NT-Password := 0x{nt}\n'
    '\tMikrotik-Group = "read"\n'
)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind(("127.0.0.1", 1812))
except OSError:
    raise SystemExit("port-busy")
finally:
    sock.close()

proc = None
try:
    write_text(users, original.rstrip() + extra)
    if remember(users) != identity:
        raise SystemExit("ownership changed")
    check = subprocess.run(
        ["sudo", "-u", "freerad", "freeradius", "-XC"],
        check=False,
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        raise SystemExit("config-check-failed")

    proc = subprocess.Popen(
        ["sudo", "-u", "freerad", "freeradius", "-f"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(1.2)

    def result(auth_type, password):
        completed = subprocess.run(
            ["radtest", "-t", auth_type, "easyhashcheck", password, "127.0.0.1", "0", secret],
            check=False,
            capture_output=True,
            text=True,
        )
        text = completed.stdout + completed.stderr
        if "Received Access-Accept" in text:
            return "accept"
        if "Received Access-Reject" in text:
            return "reject"
        return "other"

    print("pap-good", result("pap", "example-password"))
    print("mschap-good", result("mschap", "example-password"))
    print("mschap-bad", result("mschap", "example-password-99"))
finally:
    write_text(users, original)
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    if "easyhashcheck" in users.read_text(encoding="utf-8") or remember(users) != identity:
        raise SystemExit("restore-failed")
"""


def _can_try_live() -> bool:
    if not Path("/usr/bin/sudo").exists() or not Path("/usr/sbin/freeradius").exists():
        return False
    if not Path("/usr/bin/radtest").exists():
        return False
    probe = subprocess.run(["sudo", "-n", "-u", "freerad", "true"], check=False)
    if probe.returncode != 0:
        return False
    present = subprocess.run(
        ["sudo", "-n", "test", "-f", "/etc/freeradius/3.0/radiusd.conf"],
        check=False,
    )
    return present.returncode == 0


@pytest.mark.skipif(not _can_try_live(), reason="FreeRADIUS is not installed for a freerad config check")
def test_radtest_mschap_accepts_the_nt_hash_and_rejects_a_wrong_password():
    completed = subprocess.run(
        ["sudo", "-n", "env", "PYTHONPATH=/workspace", "python3", "-c", _LIVE],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 and "port-busy" in (completed.stdout + completed.stderr):
        pytest.skip("UDP 1812 is already in use")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    output = completed.stdout
    assert "pap-good accept" in output
    assert "mschap-good accept" in output
    assert "mschap-bad reject" in output
