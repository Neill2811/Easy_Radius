"""Dashboard figures from saved state and logs, shown in SAST."""

from datetime import datetime, timedelta, timezone

from easy_radius.dashboard import build_dashboard, format_sast
from easy_radius.hostcmd import CommandResult
from easy_radius.store import load_state, prepare_state, save_state
from easy_radius.web import create_app

PASSWORD = "example-password"
NOW = 1_760_000_000


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, args, timeout=120):
        self.calls.append(list(args))
        if args[:3] == ["systemctl", "is-active", "freeradius"]:
            return CommandResult(list(args), 0, "active\n", "")
        return CommandResult(list(args), 1, "", "")


def _state():
    expires = (datetime.fromtimestamp(NOW, timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    old = (datetime.fromtimestamp(NOW, timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    audit = [{"at": f"2026-10-14T09:{index:02d}:00Z", "actor": "neill", "action": "note", "detail": f"event {index}"} for index in range(12)]
    audit.append({"at": "2026-10-14T10:00:00Z", "actor": "neill", "action": "backup", "detail": "Downloaded an encrypted backup"})
    return {
        "routers": [
            {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "facts": {"version": "7.16.2", "channel": "stable"}},
            {"id": "r2", "site_name": "Example North", "ip": "192.0.2.11", "facts": {}},
            {"id": "r3", "site_name": "Example South", "ip": "192.0.2.12"},
        ],
        "firmware_latest": {"stable": "7.24.5"},
        "last_compliance": {
            "routers": [
                {"id": "r1", "site_name": "ExampleSite", "passed": 8, "total": 8, "error": "", "checks": []},
                {
                    "id": "r2",
                    "site_name": "Example North",
                    "passed": 3,
                    "total": 8,
                    "error": "",
                    "checks": [{"title": "FTP is on and restricted", "passed": False, "detail": "disabled on port 21"}],
                },
            ]
        },
        "last_backup_run": {
            "at": "2026-10-14T10:00:00Z",
            "error": "",
            "routers": [
                {"site_name": "ExampleSite", "status": "ok", "detail": ""},
                {"site_name": "Example North", "status": "failed", "detail": "connection refused"},
            ],
        },
        "monitor_alerts": [{"kind": "down", "detail": "No recent RADIUS packet"}],
        "monitor_settings": {"reject_minutes": 10, "reject_count": 5},
        "audit": audit,
        "grants": [
            {"username": "alice", "router_ids": ["r1"], "tags": ["North"], "expires_at": expires},
            {"username": "bob", "router_ids": ["r2"], "tags": [], "expires_at": old},
        ],
    }


def _auth():
    events = [
        {"time": NOW - 100, "result": "Access-Accept", "user": "alice", "nas": "192.0.2.10"},
        {"time": NOW - 5000, "result": "Access-Accept", "user": "alice", "nas": "192.0.2.11"},
    ]
    events.extend(
        {"time": NOW - 30, "result": "Access-Reject", "user": "alice", "nas": "192.0.2.10"}
        for _ in range(5)
    )
    return events


def test_dashboard_uses_saved_state_and_sast(tmp_path):
    assert format_sast("2026-10-14T10:00:00Z") == "2026-10-14 12:00 SAST"
    dash = build_dashboard(
        _state(),
        _auth(),
        [],
        now=NOW,
        health_seconds=900,
        data_dir=tmp_path,
        runner=Runner(),
    )
    assert dash["routers"] == {"up": 1, "down": 1, "unseen": 1, "total": 3, "empty": False}
    assert dash["compliance"] == {"known": True, "compliant": 1, "total": 2}
    assert dash["backup"]["ok"] == 1
    assert dash["backup"]["failed"] == 1
    assert dash["backup"]["when"] == "2026-10-14 12:00 SAST"
    assert dash["alerts"]["count"] == 1
    reasons = [item["reason"] for item in dash["attention"]]
    assert "No recent RADIUS packet" in reasons
    assert "FTP is on and restricted: disabled on port 21" in reasons
    assert "connection refused" in reasons
    assert "7.16.2 is behind 7.24.5 on stable" in reasons
    assert "Version and channel are unknown" in reasons
    assert dash["logins"]["accept"] == 2
    assert dash["logins"]["reject"] == 5
    assert dash["logins"]["hours"]
    assert any(hour["reject_h"] > 0 for hour in dash["logins"]["hours"])
    assert {"kind": "user", "label": "alice", "count": 5} in dash["logins"]["bursts"]
    assert any(burst["kind"] == "source" and burst["count"] == 5 for burst in dash["logins"]["bursts"])
    assert len(dash["activity"]) == 10
    assert dash["activity"][0]["detail"] == "Downloaded an encrypted backup"
    assert dash["activity"][0]["when"].endswith("SAST")
    assert [grant["username"] for grant in dash["grants"]] == ["alice"]
    assert "ExampleSite" in dash["grants"][0]["what"]
    assert "North" in dash["grants"][0]["what"]
    assert dash["grants"][0]["until"].endswith("SAST")
    assert dash["firmware"]["behind"] == 1
    assert dash["firmware"]["unknown"] == 2
    assert dash["server"]["freeradius"] == "Running"
    assert dash["server"]["disk"].endswith("free")
    assert dash["server"]["backup"] == "2026-10-14 12:00 SAST"
    assert PASSWORD not in str(dash)


def test_empty_dashboard_page_is_the_landing_page(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    runner = Runner()
    app = create_app(data_dir=data, runner=runner)
    app.config["TESTING"] = True
    app.config["AUTH_LOG"] = tmp_path / "auth.log"
    app.config["ACCT_LOG"] = tmp_path / "acct.log"
    client = app.test_client()
    page = client.get("/login")
    token = __import__("re").search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    logged = client.post(
        "/login",
        data={"username": "neill", "password": PASSWORD, "csrf_token": token},
    )
    assert logged.headers["Location"].endswith("/")
    body = client.get("/").get_data(as_text=True)
    assert "Dashboard" in body
    assert "None yet" in body
    assert "Not checked" in body
    assert "No config backup has been saved." in body
    assert "No stored monitoring alert." in body
    assert "Nothing needs attention." in body
    assert "No logins in the last 24 hours." in body
    assert "No history yet." in body
    assert "No temporary access is active." in body
    assert "none yet" in body
    assert "Running" in body
    assert 'aria-current="page"' in body
    assert 'title="Dashboard"' in body
    assert runner.calls == [["systemctl", "is-active", "freeradius"]]
    assert PASSWORD not in body

    state = load_state(data)
    state.update(_state())
    state["grants"][0]["expires_at"] = (datetime.now(timezone.utc) + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    save_state(data, state)
    (tmp_path / "auth.log").write_text(
        "\n".join(
            [
                f"EASYRADIUS auth time={NOW - 100} result=Access-Accept user=alice nas=192.0.2.10",
                f"EASYRADIUS auth time={NOW - 5000} result=Access-Accept user=alice nas=192.0.2.11",
            ]
            + [f"EASYRADIUS auth time={NOW - 30} result=Access-Reject user=alice nas=192.0.2.10" for _ in range(5)]
        )
        + "\n",
        encoding="utf-8",
    )
    # The page uses the clock, not the fixture timestamp, so the log lines are old.
    # The unit test covers the counts. Here we only check the saved rows render.
    shown = client.get("/").get_data(as_text=True)
    assert "1 of 2" in shown
    assert "1 ok" in shown
    assert "1 failed" in shown
    assert "2026-10-14 12:00 SAST" in shown
    assert "connection refused" in shown
    assert "7.16.2" in shown
    assert "stable" in shown
    assert "alice" in shown
    assert PASSWORD not in shown
