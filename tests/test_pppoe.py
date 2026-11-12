"""PPPoE failure lines from sample RouterOS 7 logs."""

import json
import re
from datetime import datetime, timedelta, timezone

from easy_radius.automation import automation_key, encrypt_secret
from easy_radius.dashboard import build_dashboard
from easy_radius.pppoe_failures import (
    SAST,
    aggregates,
    hot_entries,
    ingest,
    mark_removed,
    migrate_stores,
    parse_failure,
    poll_routers,
    poll_status,
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


def test_repeated_polls_stay_small_and_skip_unchanged_writes(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    state = load_state(data)
    key = automation_key(state)
    state["automation_account"] = {
        "user_id": "u1",
        "username": "radius-auto",
        "password_enc": encrypt_secret(key, PASSWORD),
    }
    state["pppoe_poll"] = {"enabled": True, "interval_minutes": 15, "threshold": 10, "last_run": ""}
    state["routers"] = [
        {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "enabled": True, "api_plaintext": False},
    ]
    users = 80
    each = 30
    start = NOW - timedelta(hours=3)
    lines = []
    for user_i in range(users):
        mac = f"AA:BB:CC:DD:{(user_i >> 8) & 0xFF:02X}:{user_i & 0xFF:02X}"
        for _nth in range(each):
            moment = start + timedelta(seconds=len(lines))
            lines.append(
                {
                    "time": moment.astimezone(SAST).strftime("%Y-%m-%d %H:%M:%S"),
                    "topics": "pppoe,ppp,error",
                    "message": f"user u{user_i} authentication failed from {mac}",
                }
            )

    class Session:
        def __init__(self, host):
            self.host = host

        def rows(self, path):
            if path == "/log":
                return holder["lines"]
            if path == "/ppp/active":
                return []
            raise AssertionError(path)

        def set(self, *args, **kwargs):
            raise AssertionError("poll must not change the router")

        def close(self):
            pass

    holder = {"lines": lines}

    def connector(host, username, password, allow_plaintext=False):
        assert host == "192.0.2.10"
        assert password == PASSWORD
        assert allow_plaintext is False
        return Session(host)

    poll_routers(state, data, connector, NOW)
    path = data / "pppoe-failures" / "r1.json"
    raw = path.read_text(encoding="utf-8")
    assert raw.startswith('{"v":2')
    assert '"events"' not in raw
    assert '"seen"' not in raw
    assert raw.count("authentication failed") == users * 10
    assert path.stat().st_size < 260_000
    rows = aggregates(data, state, NOW)
    assert sum(row["count"] for row in rows) == users * each
    assert {row["count"] for row in rows} == {each}

    blob = path.read_bytes()
    stamp = path.stat().st_mtime_ns
    for index in range(30):
        poll_routers(state, data, connector, NOW + timedelta(minutes=15 * (index + 1)))
    assert path.read_bytes() == blob
    assert path.stat().st_mtime_ns == stamp
    assert sum(row["count"] for row in aggregates(data, state, NOW + timedelta(hours=2))) == users * each

    extra = {
        "time": (NOW + timedelta(minutes=1)).astimezone(SAST).strftime("%Y-%m-%d %H:%M:%S"),
        "topics": "ppp,error",
        "message": "user u0 authentication failed from AA:BB:CC:DD:00:00 later",
    }
    holder["lines"] = lines + [extra]
    poll_routers(state, data, connector, NOW + timedelta(hours=2))
    assert path.read_bytes() != blob
    assert sum(row["count"] for row in aggregates(data, state, NOW + timedelta(hours=2))) == users * each + 1


def test_counts_use_recent_buckets_and_drop_quiet_entries(tmp_path):
    state = {"routers": [{"id": "r1", "site_name": "ExampleSite"}]}
    older = NOW - timedelta(hours=30)
    recent = NOW - timedelta(hours=1)

    def line(moment, username):
        return {
            "time": moment.astimezone(SAST).strftime("%Y-%m-%d %H:%M:%S"),
            "topics": "pppoe,error",
            "message": f"user {username} authentication failed",
        }

    ancient_at = NOW - timedelta(days=31)
    ingest(tmp_path, "r1", [line(ancient_at, "ancient")], [], ancient_at)
    assert any(row["username"] == "ancient" for row in aggregates(tmp_path, state, ancient_at))

    ingest(tmp_path, "r1", [line(older, "quiet"), line(older, "busy"), line(recent, "busy")], [], NOW)
    rows = {row["username"]: row for row in aggregates(tmp_path, state, NOW)}
    assert rows["busy"]["count"] == 1
    assert "2026-10-18" in rows["busy"]["first_seen"]
    assert rows["quiet"]["count"] == 0
    raw = (tmp_path / "pppoe-failures" / "r1.json").read_text(encoding="utf-8")
    assert "ancient" not in raw
    assert "quiet" in raw


def test_old_store_migrates_without_loading_it_all_and_missing_dir_is_empty(tmp_path, monkeypatch):
    state = {"routers": [{"id": "r1", "site_name": "ExampleSite"}]}
    missing = tmp_path / "moved-away"
    assert aggregates(missing, state, NOW) == []
    assert not missing.exists()
    migrate_stores(missing, NOW)
    assert not missing.exists()

    def event(at, username, mac, message, time):
        return {
            "key": f"{time}\n{message}",
            "time": time,
            "at": at,
            "message": message,
            "username": username,
            "mac": mac,
        }

    jsmith = []
    for second in (1, 2, 3):
        message = f"user jsmith authentication failed from {MAC} #{second}"
        stamp = f"2026-10-19 12:40:0{second}"
        jsmith.append(event(f"2026-10-19T10:40:0{second}Z", "jsmith", MAC, message, stamp))
    hidden_old = "user hidden authentication failed from " + MAC
    hidden_new = "user hidden authentication failed again from " + MAC
    events = [
        *jsmith,
        event("2026-09-01T06:00:00Z", "olduser", "", "user olduser authentication failed", "2026-09-01 08:00:00"),
        event("2026-10-19T10:00:00Z", "hidden", MAC, hidden_old, "2026-10-19 12:00:00"),
        event("2026-10-19T10:45:00Z", "hidden", MAC, hidden_new, "2026-10-19 12:45:00"),
    ]
    old = {
        "events": events,
        "seen": [f"pad-{index}-" + ("x" * 80) for index in range(8000)] + ['say "hello" } {'],
        "cleared": {},
        "removed": {f"hidden\n{MAC}": "2026-10-19T10:30:00Z"},
        "poll": {"at": "2026-10-19T10:00:00Z", "status": "ok", "detail": "kept"},
    }
    folder = tmp_path / "pppoe-failures"
    folder.mkdir()
    path = folder / "r1.json"
    path.write_text(json.dumps(old, indent=2), encoding="utf-8")
    old_size = path.stat().st_size
    assert old_size > 500_000

    seen = {"max": 0}
    real_loads = json.loads

    def wrapped_loads(text, *args, **kwargs):
        seen["max"] = max(seen["max"], len(text) if isinstance(text, str) else len(text))
        return real_loads(text, *args, **kwargs)

    def wrapped_load(handle, *args, **kwargs):
        text = handle.read()
        seen["max"] = max(seen["max"], len(text) if isinstance(text, str) else len(text))
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", wrapped_loads)
    monkeypatch.setattr(json, "load", wrapped_load)
    migrate_stores(tmp_path, NOW)
    rows = {row["username"]: row for row in aggregates(tmp_path, state, NOW)}
    assert seen["max"] < old_size // 2
    assert rows["jsmith"]["count"] == 3
    assert rows["jsmith"]["mac"] == MAC
    assert rows["hidden"]["count"] == 1
    assert "olduser" not in rows
    raw = path.read_text(encoding="utf-8")
    assert raw.startswith('{"v":2')
    assert '"events"' not in raw
    assert '"seen"' not in raw
    assert "pad-0-" not in raw
    assert "olduser" not in raw
    assert path.stat().st_size * 8 < old_size
    status = poll_status(tmp_path, state)
    assert status[0]["status"] == "ok"
    assert status[0]["detail"] == "kept"

    blob = path.read_bytes()
    ingest(
        tmp_path,
        "r1",
        [
            {"time": item["time"], "topics": "pppoe,error", "message": item["message"]}
            for item in events
        ],
        [],
        NOW,
    )
    assert path.read_bytes() == blob
    again = {row["username"]: row for row in aggregates(tmp_path, state, NOW)}
    assert again["jsmith"]["count"] == 3
    assert again["hidden"]["count"] == 1

    broken = folder / "r2.json"
    removed_key = json.dumps({f"jsmith\n{MAC}": "2026-10-19T09:00:00Z"})
    broken.write_text('{"removed": ' + removed_key + ', "events": [}', encoding="utf-8")
    migrate_stores(tmp_path, NOW)
    kept = (folder / "r2.json").read_text(encoding="utf-8")
    assert kept.startswith('{"v":2')
    assert "jsmith" in kept
    kept_rows = aggregates(tmp_path, {"routers": [{"id": "r2", "site_name": "Example North"}]}, NOW)
    assert [row for row in kept_rows if row["router_id"] == "r2"] == []
