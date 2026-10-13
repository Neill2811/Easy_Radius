import stat

from easy_radius.apply import apply_configuration
from easy_radius.configgen import parse_clients_conf, parse_users_file
from easy_radius.hostcmd import CommandResult


class FakeRunner:
    def __init__(self, xc_code=0, restart_code=0, active="active"):
        self.calls = []
        self.xc_code = xc_code
        self.restart_code = restart_code
        self.active = active

    def __call__(self, args, timeout=120):
        self.calls.append(list(args))
        if len(args) >= 2 and args[-2:] == ["freeradius", "-XC"]:
            if self.xc_code == 0:
                return CommandResult(list(args), 0, "Configuration appears to be OK.\n", "")
            return CommandResult(list(args), self.xc_code, "", "line 1: parse error\n")
        if args[:3] == ["systemctl", "restart", "freeradius"]:
            err = "" if self.restart_code == 0 else "restart failed\n"
            return CommandResult(list(args), self.restart_code, "", err)
        if args[:2] == ["journalctl", "-u"]:
            return CommandResult(list(args), 0, "journal excerpt\n", "")
        if args[:3] == ["systemctl", "is-active", "freeradius"]:
            code = 0 if self.active == "active" else 3
            return CommandResult(list(args), code, self.active + "\n", "")
        if args and args[0] == "sh":
            return CommandResult(list(args), 0, "", "")
        return CommandResult(list(args), 1, "", "unexpected command\n")


def _state():
    return {
        "localhost_secret": "example-localhost-secret",
        "routers": [
            {
                "id": "abc",
                "site_name": "ExampleSite",
                "ip": "192.0.2.10",
                "secret": "example-router-secret",
                "client_name": "example_site_192_0_2_10",
            }
        ],
        "users": [
            {
                "id": "user1",
                "username": "alice",
                "password": "example-password",
                "group": "write",
            }
        ],
    }


def test_apply_writes_config_and_restarts_when_check_passes(tmp_path):
    clients = tmp_path / "clients.conf"
    users = tmp_path / "authorize"
    clients.write_text("ORIGINAL CLIENTS\n", encoding="utf-8")
    users.write_text("ORIGINAL USERS\n", encoding="utf-8")
    before_mode = format(stat.S_IMODE(clients.stat().st_mode), "o")
    runner = FakeRunner()

    result = apply_configuration(_state(), runner, clients, users, tmp_path / "backups")

    assert result.ok
    assert result.restarted
    assert not result.rolled_back
    parsed = parse_clients_conf(clients.read_text(encoding="utf-8"))
    assert parsed["localhost_secret"] == "example-localhost-secret"
    assert parsed["routers"][0]["secret"] == "example-router-secret"
    assert parsed["routers"][0]["site_name"] == "ExampleSite"
    written_users = parse_users_file(users.read_text(encoding="utf-8"))
    assert written_users[0]["username"] == "alice"
    assert written_users[0]["group"] == "write"
    assert written_users[0]["password"].startswith("$6$")
    assert "example-password" not in users.read_text(encoding="utf-8")
    assert "Cleartext-Password" not in users.read_text(encoding="utf-8")
    assert any(call[0] == "sh" and call[-1] == before_mode for call in runner.calls)
    backup = next((tmp_path / "backups").iterdir())
    assert (backup / "clients.conf").read_text(encoding="utf-8") == "ORIGINAL CLIENTS\n"
    assert (backup / "users").read_text(encoding="utf-8") == "ORIGINAL USERS\n"
    joined = [" ".join(call) for call in runner.calls]
    assert any(call == "sudo -u freerad freeradius -XC" for call in joined)
    assert any(call == "systemctl restart freeradius" for call in joined)
    assert joined.index("sudo -u freerad freeradius -XC") < joined.index("systemctl restart freeradius")


def test_apply_restores_files_when_check_fails(tmp_path):
    clients = tmp_path / "clients.conf"
    users = tmp_path / "authorize"
    clients.write_text("ORIGINAL CLIENTS keep-this-secret\n", encoding="utf-8")
    users.write_text("ORIGINAL USERS keep-this-user\n", encoding="utf-8")
    runner = FakeRunner(xc_code=1)

    result = apply_configuration(_state(), runner, clients, users, tmp_path / "backups")

    assert not result.ok
    assert result.rolled_back
    assert not result.restarted
    assert clients.read_text(encoding="utf-8") == "ORIGINAL CLIENTS keep-this-secret\n"
    assert users.read_text(encoding="utf-8") == "ORIGINAL USERS keep-this-user\n"
    assert not any(call[:3] == ["systemctl", "restart", "freeradius"] for call in runner.calls)
    assert "freeradius -XC as freerad failed" in result.output
    assert "parse error" in result.output


def test_apply_restores_when_service_does_not_stay_active(tmp_path):
    clients = tmp_path / "clients.conf"
    users = tmp_path / "authorize"
    clients.write_text("ORIGINAL\n", encoding="utf-8")
    users.write_text("ORIGINAL\n", encoding="utf-8")
    runner = FakeRunner(active="failed")

    result = apply_configuration(_state(), runner, clients, users, tmp_path / "backups")

    assert result.rolled_back
    assert clients.read_text(encoding="utf-8") == "ORIGINAL\n"
    assert any(call[:3] == ["systemctl", "restart", "freeradius"] for call in runner.calls)


def test_apply_prints_the_journal_when_restart_fails(tmp_path):
    clients = tmp_path / "clients.conf"
    users = tmp_path / "authorize"
    clients.write_text("ORIGINAL\n", encoding="utf-8")
    users.write_text("ORIGINAL\n", encoding="utf-8")
    runner = FakeRunner(restart_code=1)

    result = apply_configuration(_state(), runner, clients, users, tmp_path / "backups")

    assert result.rolled_back
    assert clients.read_text(encoding="utf-8") == "ORIGINAL\n"
    assert any(call[:3] == ["journalctl", "-u", "freeradius"] for call in runner.calls)
    assert "journal excerpt" in result.output
    restarts = [call for call in runner.calls if call[:3] == ["systemctl", "restart", "freeradius"]]
    assert len(restarts) == 2
