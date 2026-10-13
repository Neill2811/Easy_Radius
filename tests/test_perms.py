import os
import stat
import subprocess
from pathlib import Path

import pytest

from easy_radius.perms import (
    apply_identity,
    freeradius_config_check_args,
    remember,
    write_text,
)


def test_config_check_runs_as_freerad():
    assert freeradius_config_check_args() == ["sudo", "-u", "freerad", "freeradius", "-XC"]


def test_editing_a_file_keeps_its_mode(tmp_path):
    path = tmp_path / "default"
    path.write_text("old\n", encoding="utf-8")
    os.chmod(path, 0o604)
    before = remember(path)
    write_text(path, "new\n")
    assert path.read_text(encoding="utf-8") == "new\n"
    assert remember(path)[2] == 0o604
    assert remember(path)[:2] == before[:2]


def test_new_file_is_mode_640(tmp_path):
    path = tmp_path / "easy_radius"
    write_text(path, "easy_radius_access {\n\tnoop\n}\n")
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def _sudo_freerad_ok() -> bool:
    if not os.path.exists("/usr/bin/sudo"):
        return False
    probe = subprocess.run(["sudo", "-n", "-u", "freerad", "true"], check=False)
    return probe.returncode == 0


@pytest.mark.skipif(not _sudo_freerad_ok(), reason="sudo -u freerad is not available")
def test_freerad_can_read_a_new_file_and_not_a_root_only_one(tmp_path):
    base = Path("/tmp/easy-radius-perm-check")
    if base.exists():
        subprocess.run(["sudo", "-n", "rm", "-rf", str(base)], check=True)
    base.mkdir(mode=0o755)
    secret_file = base / "clients.conf"
    secret_file.write_text("secret = example-router-secret\n", encoding="utf-8")
    os.chmod(secret_file, 0o640)
    blocked = subprocess.run(["sudo", "-n", "-u", "freerad", "test", "-r", str(secret_file)], check=False)
    assert blocked.returncode != 0

    owned = base / "sites-available"
    owned.mkdir(mode=0o755)
    target = owned / "default"
    script = (
        "from pathlib import Path\n"
        "from easy_radius.perms import remember, write_text\n"
        f"path = Path({str(target)!r})\n"
        "write_text(path, 'server default {\\n}\\n')\n"
        "before = remember(path)\n"
        "write_text(path, 'server default {\\n\\t# edited\\n}\\n')\n"
        "after = remember(path)\n"
        "raise SystemExit(0 if before == after else 1)\n"
    )
    wrote = subprocess.run(
        ["sudo", "-n", "env", "PYTHONPATH=/workspace", "python3", "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert wrote.returncode == 0, wrote.stderr
    allowed = subprocess.run(["sudo", "-n", "-u", "freerad", "test", "-r", str(target)], check=False)
    assert allowed.returncode == 0
    shown = subprocess.run(["sudo", "-n", "cat", str(target)], check=True, capture_output=True, text=True)
    assert "# edited" in shown.stdout


@pytest.mark.skipif(
    not _sudo_freerad_ok() or not os.path.exists("/usr/sbin/freeradius"),
    reason="FreeRADIUS is not installed",
)
def test_freeradius_config_check_as_freerad_user():
    present = subprocess.run(
        ["sudo", "-n", "test", "-f", "/etc/freeradius/3.0/radiusd.conf"],
        check=False,
    )
    if present.returncode != 0:
        pytest.skip("FreeRADIUS config is not installed")
    completed = subprocess.run(
        freeradius_config_check_args(),
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Configuration appears to be OK" in (completed.stdout + completed.stderr)


def test_apply_identity_uses_freerad_for_a_new_file_when_root(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("chown to freerad needs root")
    path = tmp_path / "policy"
    path.write_text("noop\n", encoding="utf-8")
    apply_identity(path, None)
    import pwd

    user = pwd.getpwnam("freerad")
    info = path.stat()
    assert info.st_uid == user.pw_uid
    assert info.st_gid == user.pw_gid
    assert stat.S_IMODE(info.st_mode) == 0o640
