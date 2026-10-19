"""PPPoE failure lines from sample RouterOS 7 logs."""

import re
from datetime import datetime, timedelta, timezone

from easy_radius.automation import automation_key, encrypt_secret
from easy_radius.dashboard import build_dashboard
from easy_radius.pppoe_failures import (
    aggregates,
    hot_entries,
    ingest,
    mark_removed,
    parse_failure,
    poll_routers,
)
from easy_radius.store import load_state, prepare_state, save_state
from easy_radius.web import create_app

PASSWORD = "example-password"
NOW = datetime(2026, 10, 19, 10, 50, tzinfo=timezone.utc)
MAC = "AA:BB:CC:DD:EE:FF"


def _lines():
    return [
        {"time": "12:40:01", "topics": "pppoe,ppp,error", "message": f"<pppoe-{MAC}>: user jsmith authentication failed"},
        {"time": "12:40:02", "topics": "pppoe,ppp,info", "message": f"<pppoe-{MAC}>: terminating... - peer is not responding"},
        {"time": "12:40:03", "topics": "pppoe,ppp,info", "message": "<pppoe-jsmith>: terminating... - authentication failed"},
        {"time": "12:40:04", "topics": "ppp,info", "message": "user jsmith authentication failed"},
        {"time": "12:40:01", "topics": "pppoe,ppp,error", "message": f"<pppoe-{MAC}>: user jsmith authentication failed"},
        {"time": "12:40:05", "topics": "pppoe,ppp,info", "message": f"<pppoe-{MAC}>: authenticated"},
        {"time": "12:40:06", "topics": "system,info", "message": "user jsmith authentication failed"},
        {"time": "12:40:07", "topics": "pppoe,ppp,info", "message": f"user \"jsmith\" authentication failed from {MAC}"},
    ]


def test_sample_routeros_lines_are_counted_deduped_and_cleared(tmp_path):
    assert parse_failure(f"<pppoe-{MAC}>: user jsmith authentication failed") == ("jsmith", MAC)
    assert parse_failure(f"<pppoe-{MAC}>: terminating... - peer is not responding") == ("", MAC)
    assert parse_failure("<pppoe-jsmith>: terminating... - authentication failed") == ("jsmith", "")
    assert parse_failure(f"<pppoe-{MAC}>: authenticated") is None

    state = {"routers": [{"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10"}]}
    ingest(tmp_path, "r1", _lines(), [], NOW)
    rows = aggregates(tmp_path, state, NOW)
    paired = next(row for row in rows if row["username"] == "jsmith" and row["mac"] == MAC)
    assert paired["count"] == 2  # the duplicate time+message is stored once
    assert paired["last_seen"] == "12:40"
    assert paired["site_name"] == "ExampleSite"
    assert any("authentication failed" in line["message"] for line in paired["lines"])
    assert PASSWORD not in str(rows)

    active = [{"name": "<pppoe-jsmith>", "caller-id": MAC, "service": "pppoe"}]
    ingest(tmp_path, "r1", _lines(), active, NOW)
    assert aggregates(tmp_path, state, NOW) == []

    later = NOW + timedelta(minutes=5)
    ingest(
        tmp_path,
        "r1",
        [{"time": "12:54:00", "topics": "pppoe,error", "message": f"<pppoe-{MAC}>: user jsmith authentication failed"}],
        [],
        later,
    )
    again = aggregates(tmp_path, state, later)
    assert len(again) == 1
    assert again[0]["count"] == 1

    mark_removed(tmp_path, "r1", "jsmith", MAC, later)
    assert aggregates(tmp_path, state, later) == []
    newest = later + timedelta(minutes=2)
    ingest(
        tmp_path,
        "r1",
        [{"time": "12:56:00", "topics": "ppp,info", "message": "user jsmith authentication failed"}],
        [],
        newest,
    )
    back = aggregates(tmp_path, state, newest)
    assert len(back) == 1
    assert back[0]["count"] == 1

    state["pppoe_poll"] = {"threshold": 1}
    assert hot_entries(tmp_path, state, newest)

    ingest(
        tmp_path,
        "r1",
        [{"time": "2026-09-01 08:00:00", "topics": "pppoe,error", "message": "<pppoe-olduser>: authentication failed"}],
        [],
        NOW,
    )
    kept = aggregates(tmp_path, state, NOW)
    assert all(row["username"] != "olduser" for row in kept)


def test_unreachable_router_is_skipped_and_the_page_lists_failures(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    state = load_state(data)
    key = automation_key(state)
    state["automation_account"] = {
        "user_id": "u1",
        "username": "radius-auto",
        "password_enc": encrypt_secret(key, PASSWORD),
    }
    state["pppoe_poll"] = {"enabled": True, "interval_minutes": 15, "threshold": 2, "last_run": ""}
    state["routers"] = [
        {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "enabled": True, "api_plaintext": False},
        {"id": "r2", "site_name": "Example North", "ip": "192.0.2.11", "enabled": True, "api_plaintext": False},
    ]
    save_state(data, state)

    class Session:
        def __init__(self, host):
            self.host = host

        def rows(self, path):
            if self.host != "192.0.2.10":
                return []
            if path == "/ppp/active":
                return []
            if path == "/log":
                return [
                    {"time": f"12:30:{index:02d}", "topics": "pppoe,ppp,error", "message": f"<pppoe-{MAC}>: user jsmith authentication failed"}
                    for index in range(3)
                ]
            raise AssertionError(path)

        def set(self, *args, **kwargs):
            raise AssertionError("poll must not change the router")

        def close(self):
            pass

    def connector(host, username, password, allow_plaintext=False):
        assert password == PASSWORD
        assert allow_plaintext is False
        if host == "192.0.2.11":
            raise OSError(f"connection refused {password}")
        return Session(host)

    poll_routers(load_state(data), data, connector, NOW)
    raw = (data / "pppoe-failures" / "r2.json").read_text(encoding="utf-8")
    assert PASSWORD not in raw
    assert "connection refused" in raw
    rows = aggregates(data, load_state(data), NOW)
    assert rows[0]["count"] == 3
    assert rows[0]["site_name"] == "ExampleSite"

    state = load_state(data)
    state["pppoe_poll"]["threshold"] = 2
    dash = build_dashboard(state, [], [], now=int(NOW.timestamp()), health_seconds=900, data_dir=data, runner=lambda args, timeout=10: None)
    assert any("jsmith" in item["reason"] and "failed attempts" in item["reason"] and item["endpoint"] == "pppoe_failures" for item in dash["attention"])

    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    app.config["AUTH_LOG"] = tmp_path / "auth.log"
    app.config["ACCT_LOG"] = tmp_path / "acct.log"
    app.config["ROUTER_CONNECT"] = connector
    client = app.test_client()
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    client.post("/login", data={"username": "neill", "password": PASSWORD, "csrf_token": token})
    body = client.get("/pppoe").get_data(as_text=True)
    assert "jsmith" in body
    assert MAC in body
    assert "failed" in body
    assert PASSWORD not in body
    filtered = client.get("/pppoe?router=r2").get_data(as_text=True)
    assert "jsmith" not in filtered
    token = re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)
    hidden = client.post(
        "/pppoe/r1/removed",
        data={"csrf_token": token, "username": "jsmith", "mac": MAC},
        follow_redirects=True,
    )
    assert "jsmith" not in hidden.get_data(as_text=True)
    assert "Hidden" in hidden.get_data(as_text=True)
