"""Firmware versions, upgrades, and the inventory export."""

import re
from pathlib import Path

from easy_radius.facts import fetch_latest, fetch_latest_stable, outdated, parse_version, read_facts, upgrade_many
from easy_radius.store import load_state, prepare_state, save_state
from easy_radius.web import create_app

PASSWORD = "example-password"


def test_version_compare_and_upstream_parse():
    from easy_radius.facts import version_label

    assert parse_version("7.16.2 (stable)") == (7, 16, 2)
    assert outdated("7.16.2", "7.24.5")
    assert not outdated("7.24.5", "7.24.5")
    assert not outdated("7.25", "7.24.5")
    assert parse_version(None) is None
    assert parse_version("") is None
    assert parse_version("   ") is None
    assert parse_version("not-a-version") is None
    assert not outdated("", "7.24.5")
    assert not outdated(None, "7.24.5")
    assert not outdated("not-a-version", "7.24.5")
    assert not outdated("7.16.2", "")
    assert version_label(None) == "unknown"
    assert version_label("  ") == "unknown"

    class Response:
        def read(self, n):
            return b"7.24.5 1790691687\n"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    assert fetch_latest_stable(lambda url, timeout=10: Response()) == "7.24.5"
    seen = []

    def opener(url, timeout=10):
        seen.append(url)
        return Response()

    assert fetch_latest("long-term", opener) == "7.24.5"
    assert seen == ["https://upgrade.mikrotik.com/routeros/NEWESTa7.long-term"]

    class Facts:
        def get(self, path):
            if path == "/system/resource":
                return {"version": "7.16.2", "architecture-name": "arm64", "board-name": "RB", "uptime": "1d"}
            if path == "/system/routerboard":
                return {"model": "RB5009", "serial-number": "SERIAL-EXAMPLE"}
            if path == "/system/license":
                return {"level": "6"}
            if path == "/system/package/update":
                return {"channel": "long-term"}
            return {}

    assert read_facts(Facts())["channel"] == "long-term"


class UpgradeRouter:
    def __init__(self, fail=False, reboot=False):
        self.fail = fail
        self.reboot = reboot
        self.events = []

    def export(self):
        self.events.append("export")
        return "# export\n"

    def call(self, path, command, **kwargs):
        self.events.append((path, command, kwargs))
        if command == "install" and self.reboot:
            raise TimeoutError("timed out")
        if self.fail and command == "check-for-updates":
            raise RuntimeError("no route to host")

    def get(self, path):
        self.events.append(("get", path))
        if path == "/system/routerboard":
            return {"routerboard": "no", "model": "CHR"}
        if path == "/system/resource":
            return {"version": "7.24.5", "architecture-name": "x86_64", "board-name": "CHR"}
        return {}

    def close(self):
        pass


def test_upgrade_backs_up_then_stops_after_a_failure(tmp_path):
    routers = [
        {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "api_plaintext": False},
        {"id": "r2", "site_name": "Example North", "ip": "192.0.2.11"},
        {"id": "r3", "site_name": "Example South", "ip": "192.0.2.12"},
    ]
    sessions = {
        "192.0.2.10": UpgradeRouter(),
        "192.0.2.11": UpgradeRouter(fail=True),
        "192.0.2.12": UpgradeRouter(),
    }

    def connector(host, username, password, allow_plaintext=False):
        assert password == PASSWORD
        assert allow_plaintext is False
        return sessions[host]

    results = upgrade_many(routers, connector, "radius-auto", PASSWORD, tmp_path, batch=1)
    assert [item["status"] for item in results] == ["ok", "failed", "skipped"]
    assert results[0]["routerboard"] == "not applicable"
    assert results[0]["routeros"] == "confirmed 7.24.5"
    assert sessions["192.0.2.10"].events[0] == "export"
    calls = [event for event in sessions["192.0.2.10"].events if isinstance(event, tuple)]
    assert ("/system/package/update", "set", {"channel": "stable"}) not in calls
    assert calls[0] == ("/system/package/update", "check-for-updates", {})
    assert ("/system/package/update", "install", {}) in calls
    assert (tmp_path / "firmware-backups" / "r1").exists()
    assert sessions["192.0.2.12"].events == []
    reboot = UpgradeRouter(reboot=True)
    one = upgrade_many([routers[0]], lambda *args, **kwargs: reboot, "radius-auto", PASSWORD, tmp_path)
    assert one[0]["status"] == "ok"
    assert one[0]["routeros"] == "confirmed 7.24.5"
    moved = UpgradeRouter()
    upgrade_many([routers[0]], lambda *args, **kwargs: moved, "radius-auto", PASSWORD, tmp_path, channel="long-term")
    assert ("/system/package/update", "set", {"channel": "long-term"}) in moved.events


class BoardSession:
    def __init__(self, board, arch="arm64", reboot_on=()):
        self.board = board
        self.arch = arch
        self.reboot_on = reboot_on
        self.events = []

    def export(self):
        self.events.append("export")
        return "# export\n"

    def call(self, path, command, **kwargs):
        self.events.append((path, command, kwargs))
        if command in self.reboot_on:
            raise TimeoutError("timed out")

    def get(self, path):
        self.events.append(("get", path))
        if path == "/system/resource":
            return {"version": "7.24.5", "architecture-name": self.arch, "board-name": "RB5009"}
        if path == "/system/routerboard":
            return dict(self.board)
        return {}

    def close(self):
        pass


def test_routerboard_firmware_is_upgraded_after_routeros_comes_back(tmp_path):
    router = {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "api_plaintext": False}
    old = {"routerboard": "yes", "current-firmware": "7.16.2", "upgrade-firmware": "7.24.5", "model": "RB5009"}
    new = {"routerboard": "yes", "current-firmware": "7.24.5", "upgrade-firmware": "7.24.5", "model": "RB5009"}
    installing = BoardSession(old, reboot_on={"install"})
    upgrading = BoardSession(old, reboot_on={"reboot"})
    returned = BoardSession(new)
    stages = iter([installing, upgrading, returned])

    def connector(host, username, password, allow_plaintext=False):
        assert password == PASSWORD
        return next(stages)

    result = upgrade_many([router], connector, "radius-auto", PASSWORD, tmp_path, routerboard=True, wait_seconds=30)
    assert result[0]["status"] == "ok"
    assert result[0]["routeros"] == "confirmed 7.24.5"
    assert result[0]["routerboard"] == "upgraded to 7.24.5"
    assert result[0]["current_firmware"] == "7.24.5"
    assert ("/system/routerboard", "upgrade", {}) in upgrading.events
    assert ("/system", "reboot", {}) in upgrading.events
    same = {"routerboard": "yes", "current-firmware": "7.24.5", "upgrade-firmware": "7.24.5"}
    before = BoardSession(same, reboot_on={"install"})
    after = BoardSession(same)

    def again(host, username, password, allow_plaintext=False):
        return before if not before.events else after

    skipped = upgrade_many([router], again, "radius-auto", PASSWORD, tmp_path)
    assert skipped[0]["routerboard"] == "already current"
    assert ("/system/routerboard", "upgrade", {}) not in before.events
    assert ("/system/routerboard", "upgrade", {}) not in after.events

    x86 = iter(
        [
            BoardSession({"routerboard": "yes", "current-firmware": "7.16.2", "upgrade-firmware": "7.24.5"}, arch="x86_64", reboot_on={"install"}),
            BoardSession({"routerboard": "yes"}, arch="x86_64"),
        ]
    )
    chr_result = upgrade_many([router], lambda *args, **kwargs: next(x86), "radius-auto", PASSWORD, tmp_path)
    assert chr_result[0]["routerboard"] == "not applicable"

    plain = iter([BoardSession(old, reboot_on={"install"}), BoardSession(old)])
    off = upgrade_many(
        [router],
        lambda *args, **kwargs: next(plain),
        "radius-auto",
        PASSWORD,
        tmp_path,
        routerboard=False,
    )
    assert off[0]["routerboard"] == "skipped"
    assert off[0]["status"] == "ok"

    opened = {"n": 0}

    def timing(host, username, password, allow_plaintext=False):
        opened["n"] += 1
        if opened["n"] == 1:
            return BoardSession(old, reboot_on={"install"})
        raise OSError(f"connection refused {password}")

    ticks = iter([0, 100])
    failed = upgrade_many(
        [router, {"id": "r2", "site_name": "Example North", "ip": "192.0.2.11"}],
        timing,
        "radius-auto",
        PASSWORD,
        tmp_path,
        batch=1,
        wait_seconds=10,
        sleep=lambda _seconds: None,
        clock=lambda: next(ticks),
    )
    assert [item["status"] for item in failed] == ["failed", "skipped"]
    assert PASSWORD not in failed[0]["detail"]
    assert "did not come back" in failed[0]["detail"]


def test_inventory_csv_and_firmware_page(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    state = load_state(data)
    state["routers"] = [
        {
            "id": "r1",
            "site_name": "ExampleSite",
            "ip": "192.0.2.10",
            "enabled": True,
            "tags": ["North"],
            "facts": {
                "model": "RB5009",
                "serial": "SERIAL-EXAMPLE",
                "version": "7.16.2",
                "channel": "stable",
                "current_firmware": "7.16.2",
                "upgrade_firmware": "7.19.1",
                "arch": "arm64",
                "uptime": "1d",
                "licence": "6",
            },
        }
    ]
    state["firmware_latest"] = "7.24.5"
    save_state(data, state)
    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/inventory").status_code == 302
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    client.post("/login", data={"username": "neill", "password": PASSWORD, "csrf_token": token})
    body = client.get("/inventory").get_data(as_text=True)
    assert "North" in body and "RB5009" in body and "SERIAL-EXAMPLE" in body
    csv_body = client.get("/inventory.csv").get_data(as_text=True)
    assert "ExampleSite,192.0.2.10,North,RB5009,SERIAL-EXAMPLE,7.16.2,stable,arm64,1d,6,yes" in csv_body
    firmware = client.get("/firmware").get_data(as_text=True)
    assert "outdated" in firmware
    assert "7.24.5" in firmware
    assert "stable" in firmware
    assert "7.19.1" in firmware
    assert "Also upgrade RouterBOARD firmware" in firmware
    assert "checked" in firmware
    state["routers"].append(
        {
            "id": "r-lt",
            "site_name": "Example Long",
            "ip": "192.0.2.14",
            "enabled": True,
            "tags": ["North"],
            "facts": {"model": "RB5009", "version": "7.16.2", "channel": "long-term"},
        }
    )
    save_state(data, state)
    channels = client.get("/firmware").get_data(as_text=True)
    assert "Example Long" in channels
    assert channels.count("outdated") == 1

    state["routers"].append(
        {"id": "r2", "site_name": "Example North", "ip": "192.0.2.11", "enabled": True, "tags": ["North"]}
    )
    state["routers"].append(
        {"id": "r3", "site_name": "Example South", "ip": "192.0.2.12", "enabled": True, "tags": [], "facts": {}}
    )
    save_state(data, state)
    missing = client.get("/firmware")
    assert missing.status_code == 200
    missing_body = missing.get_data(as_text=True)
    assert missing_body.count("unknown") >= 2
    assert "Example North" in missing_body
    inventory = client.get("/inventory")
    assert inventory.status_code == 200
    assert "unknown" in inventory.get_data(as_text=True)
    for path in ("/monitoring", "/compliance", "/reports"):
        page = client.get(path)
        assert page.status_code == 200, path
