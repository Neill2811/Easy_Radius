"""Alerts, temporary access, and PDF reports."""

import re
from datetime import datetime, timedelta, timezone

from easy_radius.access import drop_expired_grants, render_access_policy, users_with_grants
from easy_radius.apply import apply_configuration
from easy_radius.hostcmd import CommandResult
from easy_radius.logs import parse_auth_log
from easy_radius.reports import build_report
from easy_radius.store import data_path, load_state, prepare_state, save_state
from easy_radius.watch import deliver, down_alerts, login_bursts, resource_alerts, save_channel_secret
from easy_radius.web import create_app

PASSWORD = "example-password"


class Runner:
    def __call__(self, args, timeout=120):
        if args[-2:] == ["freeradius", "-XC"]:
            return CommandResult(list(args), 0, "Configuration appears to be OK.\n", "")
        if args[:3] == ["systemctl", "is-active", "freeradius"]:
            return CommandResult(list(args), 0, "active\n", "")
        if args and args[0] == "sh":
            return CommandResult(list(args), 0, "", "")
        if args[:3] == ["systemctl", "restart", "freeradius"]:
            return CommandResult(list(args), 0, "", "")
        return CommandResult(list(args), 1, "", "unexpected\n")


def test_failed_login_burst_and_resource_thresholds():
    now = 1_000_000
    events = [{"time": now - 30, "result": "Access-Reject", "user": "alice"} for _ in range(10)]
    events.append({"time": now - 30, "result": "Access-Accept", "user": "bob"})
    bursts = login_bursts(events, now, 10, 10)
    assert bursts == [{"user": "alice", "count": 10}]
    alerts = resource_alerts(
        [{"id": "r1", "site_name": "ExampleSite", "cpu": "95", "memory_used_pct": "10"}],
        90,
        90,
    )
    assert alerts[0]["kind"] == "cpu"
    down = down_alerts([{"id": "r1", "age": 1000, "up": False}, {"id": "r2", "age": None, "up": False}], {"r1": "ExampleSite"})
    assert len(down) == 1
    assert down[0]["site_name"] == "ExampleSite"


def test_temporary_access_is_in_the_policy_until_it_expires(tmp_path):
    user = {
        "id": "u1",
        "username": "alice",
        "access": "routers",
        "router_ids": [],
        "access_tags": [],
        "enabled": True,
        "password": "example-hash",
        "group": "read",
    }
    routers = [{"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "enabled": True, "secret": "example-router-secret"}]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    grants = [
        {
            "id": "g1",
            "user_id": "u1",
            "username": "alice",
            "router_ids": ["r1"],
            "tags": [],
            "expires_at": (now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": "neill",
        }
    ]
    allowed = users_with_grants([user], grants, now)
    policy = render_access_policy(allowed, routers, now)
    assert "192.0.2.10" in policy
    state = {"grants": grants}
    assert drop_expired_grants(state, now + timedelta(hours=3))
    assert state["grants"] == []
    denied = render_access_policy(users_with_grants([user], state["grants"], now), routers, now)
    assert "192.0.2.10" not in denied

    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    saved = load_state(data)
    saved["users"] = [user]
    saved["routers"] = routers
    saved["grants"] = grants
    saved["localhost_secret"] = "example-localhost-secret"
    clients = tmp_path / "clients.conf"
    users = tmp_path / "authorize"
    policy_path = tmp_path / "policy"
    clients.write_text("client localhost { ipaddr = 127.0.0.1 secret = x }\n", encoding="utf-8")
    users.write_text("# users\n", encoding="utf-8")
    result = apply_configuration(saved, Runner(), clients, users, tmp_path / "backups", policy_path)
    assert result.ok
    assert "192.0.2.10" in policy_path.read_text(encoding="utf-8")


def test_alert_secrets_stay_encrypted_and_pdf_contains_the_period(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    app = create_app(data_dir=data, runner=Runner())
    app.config["TESTING"] = True
    app.config["AUTH_LOG"] = tmp_path / "auth.log"
    (tmp_path / "auth.log").write_text(
        "EASYRADIUS auth time=1760400000 result=Access-Reject user=alice nas=192.0.2.10\n",
        encoding="utf-8",
    )
    client = app.test_client()
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    client.post("/login", data={"username": "neill", "password": PASSWORD, "csrf_token": token})
    page = client.get("/monitoring")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    saved = client.post(
        "/monitoring/settings",
        data={
            "csrf_token": token,
            "enabled": "yes",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_user": "alerts",
            "smtp_password": "example-smtp-password",
            "smtp_from": "alerts@example.com",
            "smtp_to": "neill@example.com",
            "smtp_tls": "yes",
            "telegram_chat": "1000",
            "telegram_token": "example-telegram-token",
            "cpu_pct": "90",
            "memory_pct": "90",
            "reject_count": "10",
            "interval_minutes": "15",
        },
        follow_redirects=True,
    )
    body = saved.get_data(as_text=True)
    assert "example-smtp-password" not in body
    assert "example-telegram-token" not in body
    raw = data_path(data).read_text(encoding="utf-8")
    assert "example-smtp-password" not in raw
    assert "example-telegram-token" not in raw
    state = load_state(data)
    sent = {}

    def smtp_send(**kwargs):
        sent["smtp"] = kwargs["body"]
        assert kwargs["password"] == "example-smtp-password"

    def http_post(token, chat, text):
        sent["telegram"] = (token, chat, text)

    deliver(state["monitor_settings"], state, "CPU 95%", smtp_send=smtp_send, http_post=http_post)
    assert sent["smtp"] == "CPU 95%"
    assert sent["telegram"][0] == "example-telegram-token"
    alerts = resource_alerts([{"id": "r1", "site_name": "ExampleSite", "cpu": "10", "memory_used_pct": "95"}], 90, 90)
    assert alerts[0]["kind"] == "memory"
    when = datetime(2026, 10, 14, tzinfo=timezone.utc)
    state["audit"] = [{"at": "2026-10-02T00:00:00Z", "actor": "neill", "action": "user.add", "detail": "Added alice"}]
    pdf = build_report(state, (tmp_path / "auth.log").read_text(encoding="utf-8"), when=when, month="2026-10")
    assert pdf.startswith(b"%PDF")
    assert b"Added alice" in pdf
    page = client.get("/reports")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    downloaded = client.post("/reports/download", data={"csrf_token": token, "month": "2026-10"})
    assert downloaded.mimetype == "application/pdf"
    assert downloaded.data.startswith(b"%PDF")
    assert any(event["detail"].startswith("Downloaded") for event in load_state(data)["audit"])
