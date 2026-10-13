import json
import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"


def _env(tmp_path: Path, **extra) -> dict:
    env = os.environ.copy()
    env.update(
        {
            "EASY_RADIUS_APP_DIR": str(tmp_path / "app"),
            "EASY_RADIUS_FREERADIUS_DIR": str(tmp_path / "freeradius"),
            "EASY_RADIUS_BACKUP_ROOT": str(tmp_path / "backups"),
            "EASY_RADIUS_SKIP_PACKAGES": "1",
            "EASY_RADIUS_SKIP_DOCKER": "1",
            "SSH_CONNECTION": "",
            "SSH_CLIENT": "",
        }
    )
    env.update(extra)
    return env


def _run(tmp_path: Path, args: list[str], env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(INSTALL), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_fresh_install_writes_starter_and_is_idempotent(tmp_path):
    env = _env(tmp_path)
    first = _run(tmp_path, [], env)
    assert first.returncode == 0, first.stderr + first.stdout
    clients = tmp_path / "freeradius" / "clients.conf"
    users = tmp_path / "freeradius" / "mods-config" / "files" / "authorize"
    data = json.loads((tmp_path / "app" / "data" / "data.json").read_text(encoding="utf-8"))
    text = clients.read_text(encoding="utf-8")
    assert "client localhost {" in text
    assert data["localhost_secret"] in text
    assert data["admin_password_hash"] == ""
    assert "Cleartext-Password" not in users.read_text(encoding="utf-8")
    mode = stat.S_IMODE(clients.stat().st_mode)
    assert mode == 0o640

    before = clients.read_bytes()
    second = _run(tmp_path, [], env)
    assert second.returncode == 0, second.stderr + second.stdout
    assert clients.read_bytes() == before
    again = json.loads((tmp_path / "app" / "data" / "data.json").read_text(encoding="utf-8"))
    assert again["localhost_secret"] == data["localhost_secret"]
    assert "not overwritten" in second.stdout


def test_existing_config_is_backed_up_and_not_overwritten(tmp_path):
    freeradius = tmp_path / "freeradius"
    users = freeradius / "mods-config" / "files"
    users.mkdir(parents=True)
    original_clients = "client keep_me {\n    ipaddr = 192.0.2.20\n    secret = leave-this-secret\n}\n"
    original_users = "# leave this users file\n"
    (freeradius / "clients.conf").write_text(original_clients, encoding="utf-8")
    (users / "authorize").write_text(original_users, encoding="utf-8")

    result = _run(tmp_path, [], _env(tmp_path))
    assert result.returncode == 0, result.stderr + result.stdout
    assert (freeradius / "clients.conf").read_text(encoding="utf-8") == original_clients
    assert (users / "authorize").read_text(encoding="utf-8") == original_users
    backups = list((tmp_path / "backups").glob("freeradius-backup-*"))
    assert backups
    saved = (backups[0] / "freeradius" / "clients.conf").read_text(encoding="utf-8")
    assert saved == original_clients
    data = json.loads((tmp_path / "app" / "data" / "data.json").read_text(encoding="utf-8"))
    assert data["localhost_secret"]
    assert data["localhost_secret"] not in original_clients
    assert data["routers"] == []
    assert data["users"] == []
    assert "not imported" in result.stdout


def test_ufw_refuses_to_enable_when_ssh_client_would_be_locked_out(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "ufw.log"
    ufw = bin_dir / "ufw"
    ufw.write_text("#!/bin/sh\necho \"$@\" >> \"$UFW_LOG\"\n", encoding="utf-8")
    ufw.chmod(0o755)
    env = _env(
        tmp_path,
        SSH_CONNECTION="203.0.113.10 40000 192.0.2.1 22",
        PATH=f"{bin_dir}:{os.environ['PATH']}",
        UFW_LOG=str(log),
    )
    result = _run(
        tmp_path,
        ["--ufw", "--admin-subnets", "192.0.2.0/24", "--router-subnets", "198.51.100.0/24"],
        env,
    )
    assert result.returncode == 1
    assert "Refusing to enable ufw" in result.stderr
    assert "203.0.113.10" in result.stderr
    assert not log.exists()


def test_ufw_adds_allows_before_enable_when_ssh_client_is_included(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "ufw.log"
    ufw = bin_dir / "ufw"
    ufw.write_text("#!/bin/sh\necho \"$@\" >> \"$UFW_LOG\"\n", encoding="utf-8")
    ufw.chmod(0o755)
    env = _env(
        tmp_path,
        SSH_CONNECTION="192.0.2.10 40000 192.0.2.1 22",
        PATH=f"{bin_dir}:{os.environ['PATH']}",
        UFW_LOG=str(log),
    )
    result = _run(
        tmp_path,
        ["--ufw", "--admin-subnets", "192.0.2.0/24", "--router-subnets", "198.51.100.0/24"],
        env,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    lines = log.read_text(encoding="utf-8").splitlines()
    enable_at = next(index for index, line in enumerate(lines) if line.startswith("--force enable"))
    earlier = "\n".join(lines[:enable_at])
    assert "default deny incoming" in earlier
    assert "to any port 22 proto tcp" in earlier
    assert "to any port 8088 proto tcp" in earlier
    assert "to any port 1812 proto udp" in earlier
    assert "to any port 1813 proto udp" in earlier
    assert "192.0.2.0/24" in earlier
    assert "198.51.100.0/24" in earlier
