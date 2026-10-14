"""Scheduled exports, diffs, and compliance checks."""

import re
from datetime import datetime, timezone
from pathlib import Path

from easy_radius.compliance import evaluate, fix_template, score
from easy_radius.config_backups import backup_due, diff_versions, normalize_export, prune, run_backups
from easy_radius.store import load_state, prepare_state, save_state
from easy_radius.web import create_app

PASSWORD = "example-password"


class ExportSession:
    def __init__(self, text):
        self.text = text

    def export(self):
        return self.text

    def close(self):
        pass


def test_header_only_difference_is_not_a_change_and_old_files_are_removed(tmp_path):
    older = "# 2026-01-01 00:00:00 by RouterOS 7.16\n/ip dns\nset servers=192.0.2.53\n"
    newer = "# 2026-01-02 00:00:00 by RouterOS 7.16\n/ip dns\nset servers=192.0.2.53\n"
    assert normalize_export(older) == normalize_export(newer)
    assert diff_versions(older, newer) == ""
    changed = newer + "set allow-remote-requests=no\n"
    assert "allow-remote-requests" in diff_versions(older, changed)
    folder = tmp_path / "router-backups" / "r1"
    folder.mkdir(parents=True)
    (folder / "20200101T000000Z.rsc").write_text("old\n", encoding="utf-8")
    (folder / "20261001T000000Z.rsc").write_text("new\n", encoding="utf-8")
    removed = prune(tmp_path, "r1", 30, datetime(2026, 10, 14, tzinfo=timezone.utc))
    assert removed == 1
    assert not (folder / "20200101T000000Z.rsc").exists()
    assert backup_due({"enabled": True, "hour": 2, "last_run": ""}, datetime(2026, 10, 14, 3, tzinfo=timezone.utc))
    assert not backup_due({"enabled": True, "hour": 2, "last_run": "2026-10-14T02:00:00Z"}, datetime(2026, 10, 14, 3, tzinfo=timezone.utc))


def test_outside_change_is_recorded_unless_easy_radius_touched_the_router(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    state = load_state(data)
    state["routers"] = [
        {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "enabled": True, "api_plaintext": False}
    ]
    from easy_radius.automation import automation_key, encrypt_secret

    key = automation_key(state)
    state["automation_account"] = {"user_id": "u1", "username": "radius-auto", "password_enc": encrypt_secret(key, PASSWORD)}
    texts = iter(
        [
            "# 2026-01-01 00:00:00 by RouterOS 7.16\n/ip dns\nset servers=192.0.2.1\n",
            "# 2026-01-02 00:00:00 by RouterOS 7.16\n/ip dns\nset servers=192.0.2.53\n",
        ]
    )

    def connector(host, username, password, allow_plaintext=False):
        assert allow_plaintext is False
        assert password == PASSWORD
        return ExportSession(next(texts))

    run_backups(state, data, connector, actor="scheduler", now=datetime(2026, 10, 1, tzinfo=timezone.utc))
    run_backups(state, data, connector, actor="scheduler", now=datetime(2026, 10, 2, tzinfo=timezone.utc))
    assert state["change_alerts"]
    assert any("outside Easy Radius" in event["detail"] for event in state["audit"])
    assert PASSWORD not in " ".join(event["detail"] for event in state["audit"])
    state["router_touches"] = {"r1": "2026-10-03T00:00:00Z"}
    # A third export that differs, after a touch, is not an outside change.
    # Rebind the iterator by replacing connector closure: call with a fresh one.
    def later(host, username, password, allow_plaintext=False):
        return ExportSession("# 2026-10-04 00:00:00 by RouterOS 7.16\n/ip dns\nset servers=192.0.2.9\n")

    before = len(state["change_alerts"])
    run_backups(state, data, later, actor="neill", now=datetime(2026, 10, 4, tzinfo=timezone.utc))
    assert len(state["change_alerts"]) == before


def test_compliance_score_and_fix_steps():
    class Router:
        def rows(self, path):
            if path == "/ip/service":
                return [
                    {"name": "telnet", "port": "23", "disabled": "false"},
                    {"name": "ftp", "port": "21", "disabled": "true", "address": "192.0.2.10/32"},
                    {"name": "ssh", "port": "22", "disabled": "false", "address": ""},
                    {"name": "winbox", "port": "8291", "disabled": "false", "address": ""},
                    {"name": "www", "port": "80", "disabled": "false"},
                    {"name": "www-ssl", "port": "443", "disabled": "true"},
                    {"name": "api", "port": "8728", "disabled": "false"},
                    {"name": "api-ssl", "port": "8729", "disabled": "false", "address": ""},
                ]
            if path == "/user":
                return [{"name": "admin", "disabled": "false"}]
            return []

        def get(self, path):
            if path == "/system/ntp/client":
                return {"enabled": "false", "servers": ""}
            if path == "/user/aaa":
                return {"use-radius": "no"}
            if path == "/snmp":
                return {"enabled": "no"}
            rows = self.rows(path)
            return rows[0] if rows else {}

    checks = evaluate(Router())
    passed, total = score(checks)
    assert total == 12
    by_id = {check["id"]: check for check in checks}
    assert by_id["ftp"]["passed"] is False
    assert by_id["ftp"]["detail"] == "disabled on port 21"
    assert by_id["telnet"]["detail"] == "enabled on port 23, open to any address"
    assert by_id["www"]["title"] == "www is off"
    assert by_id["www"]["passed"] is False
    assert by_id["www-ssl"]["title"] == "www-ssl is off"
    assert by_id["www-ssl"]["passed"] is True
    assert by_id["www-ssl"]["detail"] == "disabled on port 443"
    assert by_id["ssh"]["passed"] is True
    assert by_id["ssh"]["detail"] == "enabled on port 22, open to any address"
    assert by_id["winbox"]["passed"] is False
    assert by_id["winbox"]["detail"] == "enabled on port 8291, open to any address"
    assert by_id["api"]["detail"] == "enabled on port 8728, open to any address"
    assert by_id["api-ssl"]["detail"] == "enabled on port 8729, open to any address"
    assert by_id["snmp"]["passed"] is True
    assert passed == 3  # www-ssl is off, SSH is report-only, SNMP has no communities
    template = fix_template("192.0.2.1")
    paths = [(step.path, step.where, step.values) for step in template.steps]
    assert ("/ip/service", {"name": "telnet"}, {"disabled": "yes"}) in paths
    assert ("/ip/service", {"name": "www"}, {"disabled": "yes"}) in paths
    assert ("/ip/service", {"name": "www-ssl"}, {"disabled": "yes"}) in paths
    assert not any(step.where.get("name") in {"api", "ftp", "winbox", "ssh"} for step in template.steps)
    assert any(step.where.get("name") == "api-ssl" and step.values["address"] == "192.0.2.1/32" for step in template.steps)


def test_ftp_passes_only_when_enabled_and_restricted():
    from easy_radius.compliance import _ftp

    assert _ftp({"name": "ftp", "port": "21", "disabled": "true", "address": "192.0.2.10/32"}) == (
        False,
        "disabled on port 21",
    )
    assert _ftp(None) == (False, "not present")
    limited = _ftp(
        {"name": "ftp", "port": "21", "disabled": "false", "address": "192.0.2.10/32,198.51.100.5/32"}
    )
    assert limited == (True, "enabled on port 21, restricted to 192.0.2.10/32,198.51.100.5/32")
    assert _ftp({"name": "ftp", "port": "21", "disabled": "no", "address": "0.0.0.0/0"}) == (
        False,
        "enabled on port 21, open to any address",
    )
    assert _ftp({"name": "ftp", "port": "21", "disabled": "false", "address": ""}) == (
        False,
        "enabled on port 21, open to any address",
    )
    assert _ftp({"name": "ftp", "port": "21", "disabled": "no", "address": "::/0"}) == (
        False,
        "enabled on port 21, open to any address",
    )
    assert not any(step.where.get("name") == "ftp" for step in fix_template("").steps)


def test_winbox_fails_only_when_enabled_with_no_addresses():
    from easy_radius.compliance import _winbox

    assert _winbox({"name": "winbox", "port": "8291", "disabled": "true", "address": ""}) == (
        True,
        "disabled on port 8291",
    )
    assert _winbox(None) == (True, "not present")
    limited = _winbox({"name": "winbox", "port": "8291", "disabled": "false", "address": "192.0.2.0/24"})
    assert limited == (True, "enabled on port 8291, restricted to 192.0.2.0/24")
    assert _winbox({"name": "winbox", "port": "8291", "disabled": "no", "address": ""}) == (
        False,
        "enabled on port 8291, open to any address",
    )
    assert _winbox({"name": "winbox", "port": "8291", "disabled": "false", "address": "0.0.0.0/0"}) == (
        False,
        "enabled on port 8291, open to any address",
    )
    assert _winbox({"name": "winbox", "port": "8291", "disabled": "false", "address": "::/0"}) == (
        False,
        "enabled on port 8291, open to any address",
    )
    assert not any(step.where.get("name") == "winbox" for step in fix_template("192.0.2.1").steps)


def test_snmp_lists_communities_without_secrets_and_fails_public_or_open_write():
    from easy_radius.compliance import _snmp

    secret = "example-community-secret"
    privacy = "example-privacy-value"

    class Router:
        def __init__(self, communities, enabled="yes"):
            self.communities = communities
            self.enabled = enabled

        def get(self, path):
            if path == "/snmp":
                return {"enabled": self.enabled}
            return {}

        def rows(self, path):
            if path == "/snmp/community":
                return self.communities
            return []

    safe = Router(
        [
            {
                "name": "monitor",
                "addresses": "192.0.2.10/32",
                "read-access": "yes",
                "write-access": "no",
                "security": "none",
                "authentication-password": secret,
                "encryption-password": privacy,
            }
        ]
    )
    passed, detail = _snmp(safe)
    assert passed is True
    assert detail == "SNMP enabled; monitor (enabled, 192.0.2.10/32, read, security none)"
    assert secret not in detail
    assert privacy not in detail

    public = Router(
        [
            {
                "name": "public",
                "address": "192.0.2.10/32",
                "read-access": "yes",
                "write-access": "no",
                "security": "none",
                "disabled": "false",
            }
        ]
    )
    passed, detail = _snmp(public)
    assert passed is False
    assert "public community is enabled" in detail
    assert secret not in detail

    disabled_public = Router(
        [
            {
                "name": "public",
                "address": "",
                "read-access": "yes",
                "write-access": "yes",
                "security": "none",
                "disabled": "yes",
                "authentication-password": secret,
            }
        ],
        enabled="no",
    )
    passed, detail = _snmp(disabled_public)
    assert passed is True
    assert "SNMP disabled" in detail
    assert secret not in detail

    open_write = Router(
        [
            {
                "name": "ops",
                "address": "0.0.0.0/0",
                "read-access": "yes",
                "write-access": "yes",
                "security": "private",
                "disabled": "no",
                "authentication-password": secret,
            }
        ]
    )
    passed, detail = _snmp(open_write)
    assert passed is False
    assert "ops has write access with no address restriction" in detail
    assert "read-write" in detail
    assert "security private" in detail
    assert secret not in detail

    limited_write = Router(
        [
            {
                "name": "ops",
                "addresses": "198.51.100.5/32",
                "read-access": "yes",
                "write-access": "true",
                "security": "authorized",
                "disabled": "false",
            }
        ]
    )
    passed, detail = _snmp(limited_write)
    assert passed is True
    assert "198.51.100.5/32" in detail
    assert "read-write" in detail


def test_plaintext_api_passes_when_disabled_or_limited_to_addresses():
    from easy_radius.compliance import _plaintext_api

    assert _plaintext_api({"name": "api", "port": "8728", "disabled": "true", "address": ""}) == (
        True,
        "disabled on port 8728",
    )
    assert _plaintext_api(None) == (True, "not present")
    limited = _plaintext_api(
        {"name": "api", "port": "8728", "disabled": "false", "address": "192.0.2.10/32,198.51.100.5/32"}
    )
    assert limited == (True, "enabled on port 8728, restricted to 192.0.2.10/32,198.51.100.5/32")
    assert _plaintext_api({"name": "api", "port": "8728", "disabled": "no", "address": "0.0.0.0/0"}) == (
        False,
        "enabled on port 8728, open to any address",
    )
    assert _plaintext_api({"name": "api", "port": "8728", "disabled": "false", "address": ""}) == (
        False,
        "enabled on port 8728, open to any address",
    )


def test_failed_routers_are_listed_before_compliant_ones():
    from easy_radius.compliance import present_report

    report = present_report(
        {
            "at": "2026-10-14T00:00:00Z",
            "routers": [
                {"id": "ok", "site_name": "Example North", "ip": "192.0.2.11", "passed": 8, "total": 8, "error": ""},
                {"id": "bad", "site_name": "ExampleSite", "ip": "192.0.2.10", "passed": 7, "total": 8, "error": ""},
                {"id": "down", "site_name": "Example South", "ip": "192.0.2.12", "passed": 0, "total": 0, "error": "connection refused"},
            ],
        }
    )
    assert [router["site_name"] for router in report["routers"]] == [
        "ExampleSite",
        "Example South",
        "Example North",
    ]
    assert [router["compliant"] for router in report["routers"]] == [False, False, True]
    assert report["compliant"] == 1
    assert report["router_count"] == 3


def test_compliance_page_keeps_check_details_without_a_service_table(tmp_path):
    secret = "example-community-secret"
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    state = load_state(data)
    state["routers"] = [
        {"id": "r-ok", "site_name": "Example North", "ip": "192.0.2.11", "enabled": True, "api_plaintext": False},
        {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "enabled": True, "api_plaintext": False},
    ]
    from easy_radius.automation import automation_key, encrypt_secret

    key = automation_key(state)
    state["automation_account"] = {
        "user_id": "u1",
        "username": "radius-auto",
        "password_enc": encrypt_secret(key, PASSWORD),
    }
    save_state(data, state)

    class Passing:
        def rows(self, path):
            if path == "/ip/service":
                return [
                    {"name": "telnet", "port": "23", "disabled": "true"},
                    {"name": "ftp", "port": "21", "disabled": "false", "address": "192.0.2.10/32"},
                    {"name": "ssh", "port": "22", "disabled": "false", "address": "192.0.2.10/32"},
                    {"name": "winbox", "port": "8291", "disabled": "false", "address": "192.0.2.0/24"},
                    {"name": "www", "port": "80", "disabled": "true"},
                    {"name": "www-ssl", "port": "443", "disabled": "true"},
                    {"name": "api", "port": "8728", "disabled": "true"},
                    {"name": "api-ssl", "port": "8729", "disabled": "false", "address": "192.0.2.1/32"},
                ]
            if path == "/user":
                return [{"name": "admin", "disabled": "yes"}]
            if path == "/snmp/community":
                return [
                    {
                        "name": "monitor",
                        "addresses": "192.0.2.10/32",
                        "read-access": "yes",
                        "write-access": "no",
                        "security": "none",
                    }
                ]
            return []

        def get(self, path):
            if path == "/system/ntp/client":
                return {"enabled": "true", "servers": "192.0.2.53"}
            if path == "/user/aaa":
                return {"use-radius": "yes"}
            if path == "/snmp":
                return {"enabled": "yes"}
            return {}

        def close(self):
            pass

    class Session:
        def rows(self, path):
            if path == "/ip/service":
                return [
                    {"name": "winbox", "port": "8291", "disabled": "false", "address": "192.0.2.0/24"},
                    {"name": "www", "port": "80", "disabled": "true"},
                    {"name": "www-ssl", "port": "443", "disabled": "false"},
                    {"name": "ssh", "port": "22", "disabled": "false", "address": "192.0.2.10/32"},
                ]
            if path == "/user":
                return [{"name": "admin", "disabled": "yes"}]
            if path == "/snmp/community":
                return [
                    {
                        "name": "monitor",
                        "addresses": "192.0.2.10/32",
                        "read-access": "yes",
                        "write-access": "no",
                        "security": "none",
                        "authentication-password": secret,
                    }
                ]
            return []

        def get(self, path):
            if path == "/system/ntp/client":
                return {"enabled": "true", "servers": "192.0.2.53"}
            if path == "/user/aaa":
                return {"use-radius": "yes"}
            if path == "/snmp":
                return {"enabled": "yes"}
            return {}

        def close(self):
            pass

    def connector(host, username, password, allow_plaintext=False):
        assert password == PASSWORD
        if host == "192.0.2.11":
            return Passing()
        return Session()

    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    app.config["ROUTER_CONNECT"] = connector
    client = app.test_client()
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    client.post("/login", data={"username": "neill", "password": PASSWORD, "csrf_token": token})
    page = client.get("/compliance")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    checked = client.post("/compliance/check", data={"csrf_token": token}, follow_redirects=True)
    body = checked.get_data(as_text=True)
    assert "1 of 2 routers compliant" in body
    assert "12/12" in body
    assert body.index("ExampleSite") < body.index("Example North")
    assert '<details class="router-row">' in body
    assert re.search(r'<details class="router-row"[^>]*\bopen\b', body) is None
    assert "enabled on port 8291, restricted to 192.0.2.0/24" in body
    assert "Winbox is off or restricted" in body
    assert "www is off" in body
    assert "www-ssl is off" in body
    assert "disabled on port 80" in body
    assert "enabled on port 22, restricted to 192.0.2.10/32" in body
    assert "monitor" in body
    assert 'name="router_ids" value="r1"' in body
    assert 'value="r-ok"' not in body
    assert "Fix ticked routers" in body
    assert "Allowed addresses" not in body
    assert ">Services<" not in body
    assert secret not in body
    assert PASSWORD not in body


def test_backup_page_requires_login_and_schedule_saves(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/backups").status_code == 302
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    client.post("/login", data={"username": "neill", "password": PASSWORD, "csrf_token": token})
    page = client.get("/backups")
    assert "Nightly backups" in page.get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    client.post(
        "/backups/settings",
        data={"csrf_token": token, "enabled": "yes", "hour": "4", "retention_days": "14"},
        follow_redirects=True,
    )
    saved = load_state(data)["backup_schedule"]
    assert saved["hour"] == 4
    assert saved["retention_days"] == 14
    assert any(event["actor"] == "neill" for event in load_state(data)["audit"])


def test_backup_failure_is_explained_and_kept(tmp_path):
    from easy_radius.config_backups import complete_backup, explain_backup_error
    from easy_radius.ops_web import _maybe_backup

    assert explain_backup_error("SSL handshake failure") == "api-ssl has no certificate"
    assert explain_backup_error("connection refused") == "connection refused"
    assert explain_backup_error("timed out") == "timed out"
    assert (
        explain_backup_error(f"invalid user name or password ({PASSWORD})", PASSWORD)
        == "service account rejected; check Apply/permissions"
    )
    assert PASSWORD not in explain_backup_error(f"invalid user name or password ({PASSWORD})", PASSWORD)

    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    state = load_state(data)
    state["routers"] = [
        {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "enabled": True, "api_plaintext": False}
    ]
    from easy_radius.automation import automation_key, encrypt_secret

    key = automation_key(state)
    state["automation_account"] = {
        "user_id": "u1",
        "username": "radius-auto",
        "password_enc": encrypt_secret(key, PASSWORD),
    }
    state["backup_schedule"] = {"enabled": True, "hour": 0, "retention_days": 30, "last_run": ""}
    save_state(data, state)

    def connector(host, username, password, allow_plaintext=False):
        raise OSError(f"SSL: handshake failure ({password})")

    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    app.config["ROUTER_CONNECT"] = connector
    client = app.test_client()
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    client.post("/login", data={"username": "neill", "password": PASSWORD, "csrf_token": token})
    page = client.get("/backups")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    done = client.post("/backups/run", data={"csrf_token": token}, follow_redirects=True)
    body = done.get_data(as_text=True)
    assert "Some config backups failed." in body
    assert "api-ssl has no certificate" in body
    assert "Last backup:" in body
    assert "failed:" in body
    assert PASSWORD not in body
    saved = load_state(data)
    assert saved["last_backup_run"]["routers"][0]["status"] == "failed"
    assert any("Backup failed for ExampleSite" in event["detail"] for event in saved["audit"])
    assert PASSWORD not in " ".join(event["detail"] for event in saved["audit"])
    history = client.get("/history")
    assert "Backup failed for ExampleSite" in history.get_data(as_text=True)
    assert PASSWORD not in history.get_data(as_text=True)

    state = load_state(data)
    state["automation_account"] = {}
    state["backup_schedule"]["last_run"] = ""
    save_state(data, state)
    _maybe_backup(app)
    scheduled = load_state(data)
    assert scheduled["last_backup_run"]["error"]
    assert scheduled["backup_schedule"]["last_run"]
    assert any(event["actor"] == "scheduler" and "Backup failed" in event["detail"] for event in scheduled["audit"])

    state = load_state(data)
    state["automation_account"] = {
        "user_id": "u1",
        "username": "radius-auto",
        "password_enc": encrypt_secret(automation_key(state), PASSWORD),
    }
    state["backup_schedule"]["last_run"] = ""
    save_state(data, state)

    def refused(host, username, password, allow_plaintext=False):
        raise OSError("connection refused")

    app.config["ROUTER_CONNECT"] = refused
    summary = complete_backup(load_state(data), data, refused, actor="scheduler")
    assert summary["routers"][0]["detail"] == "connection refused"
