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
                    {"name": "telnet", "disabled": "false"},
                    {"name": "ftp", "disabled": "true"},
                    {"name": "www", "disabled": "false"},
                    {"name": "api", "disabled": "false"},
                    {"name": "api-ssl", "disabled": "false", "address": ""},
                ]
            if path == "/user":
                return [{"name": "admin", "disabled": "false"}]
            return []

        def get(self, path):
            if path == "/system/ntp/client":
                return {"enabled": "false", "servers": ""}
            if path == "/user/aaa":
                return {"use-radius": "no"}
            rows = self.rows(path)
            return rows[0] if rows else {}

    checks = evaluate(Router())
    passed, total = score(checks)
    assert total == 8
    assert passed == 1  # ftp is already off
    template = fix_template("192.0.2.1")
    paths = [(step.path, step.where, step.values) for step in template.steps]
    assert ("/ip/service", {"name": "telnet"}, {"disabled": "yes"}) in paths
    assert any(step.where.get("name") == "api-ssl" and step.values["address"] == "192.0.2.1/32" for step in template.steps)


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
