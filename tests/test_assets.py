"""Firmware versions, upgrades, and the inventory export."""

import re
from pathlib import Path

from easy_radius.facts import fetch_latest_stable, outdated, parse_version, upgrade_many
from easy_radius.store import load_state, prepare_state, save_state
from easy_radius.web import create_app

PASSWORD = "example-password"


def test_version_compare_and_upstream_parse():
    assert parse_version("7.16.2 (stable)") == (7, 16, 2)
    assert outdated("7.16.2", "7.24.5")
    assert not outdated("7.24.5", "7.24.5")
    assert not outdated("7.25", "7.24.5")

    class Response:
        def read(self, n):
            return b"7.24.5 1790691687\n"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    assert fetch_latest_stable(lambda url, timeout=10: Response()) == "7.24.5"


class UpgradeRouter:
    def __init__(self, fail=False, reboot=False):
        self.fail = fail
        self.reboot = reboot
        self.events = []

    def export(self):
        self.events.append("export")
        return "# export\n"

    def call(self, path, command, **kwargs):
        self.events.append((path, command))
        if command == "install" and self.reboot:
            raise TimeoutError("timed out")
        if self.fail and command == "check-for-updates":
            raise RuntimeError("no route to host")

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
    assert [item["status"] for item in results] == ["started", "failed", "skipped"]
    assert sessions["192.0.2.10"].events[0] == "export"
    assert ("/system/package/update", "install") in sessions["192.0.2.10"].events
    assert (tmp_path / "firmware-backups" / "r1").exists()
    assert sessions["192.0.2.12"].events == []
    reboot = UpgradeRouter(reboot=True)
    one = upgrade_many([routers[0]], lambda *args, **kwargs: reboot, "radius-auto", PASSWORD, tmp_path)
    assert one[0]["status"] == "started"


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
            "facts": {"model": "RB5009", "serial": "SERIAL-EXAMPLE", "version": "7.16.2", "arch": "arm64", "uptime": "1d", "licence": "6"},
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
    assert "ExampleSite,192.0.2.10,North,RB5009,SERIAL-EXAMPLE,7.16.2,arm64,1d,6,yes" in csv_body
    firmware = client.get("/firmware").get_data(as_text=True)
    assert "outdated" in firmware
    assert "7.24.5" in firmware
