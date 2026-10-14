"""RouterOS automation: tasks, dry-run, batches, and the service account."""

import json
import re
from pathlib import Path

from easy_radius.automation import (
    AutomationError,
    account_password,
    decrypt_secret,
    encrypt_secret,
    parse_template,
    plan_changes,
    same_value,
    select_targets,
)
from easy_radius.store import data_path, load_state, prepare_state
from easy_radius.web import create_app

PASSWORD = "example-password"
TASK = """
name: Set DNS
variables:
  dns_servers: "192.0.2.53,192.0.2.54"
steps:
  - path: /ip/dns
    set:
      servers: "{{ dns_servers }}"
      allow-remote-requests: "no"
"""
COMMAND_TASK = """
- /system/identity set name={{ identity_name }}
"""


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


class FakeRouter:
    def __init__(self, values, fail=False):
        self.values = {path: dict(row) for path, row in values.items()}
        self.fail = fail
        self.events = []
        self.restored = None

    def get(self, path):
        self.events.append(("get", path))
        return dict(self.values.get(path, {}))

    def set(self, path, values):
        self.events.append(("set", path, dict(values)))
        if self.fail:
            raise AutomationError("write refused")
        self.values.setdefault(path, {}).update(values)

    def export(self):
        self.events.append(("export",))
        return "# example export\n/ip dns\nset servers=192.0.2.1\n"

    def restore(self, text):
        self.restored = text

    def close(self):
        self.events.append(("close",))


def _routers():
    return [
        {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "enabled": True, "tags": ["North"]},
        {"id": "r2", "site_name": "Example North", "ip": "192.0.2.11", "enabled": True, "tags": ["North"]},
        {"id": "r3", "site_name": "Example South", "ip": "192.0.2.12", "enabled": True, "tags": ["South"]},
        {"id": "r4", "site_name": "Example Off", "ip": "192.0.2.13", "enabled": False, "tags": ["North"]},
    ]


def test_templates_accept_paths_and_commands_and_skip_unchanged_values():
    parsed = parse_template(TASK)
    assert parsed.name == "Set DNS"
    assert parsed.variables["dns_servers"].startswith("192.0.2.53")
    command = parse_template(COMMAND_TASK)
    assert command.steps[0].path == "/system/identity"
    assert same_value("true", "yes")
    assert same_value("no", "false")
    assert plan_changes({"servers": "192.0.2.1", "allow-remote-requests": "false"}, {"servers": "192.0.2.53", "allow-remote-requests": "no"}) == {
        "servers": "192.0.2.53"
    }
    builtins = parse_template(Path("easy_radius/tasks/ntp.yml").read_text(encoding="utf-8"))
    assert builtins.steps[0].path == "/system/ntp/client"


def test_targets_come_from_routers_and_site_groups():
    chosen = select_targets(_routers(), ["r3"], ["North"])
    assert [router["site_name"] for router in chosen] == ["Example South", "ExampleSite", "Example North"]
    assert select_targets(_routers(), ["r4"], []) == []
    try:
        select_targets(_routers(), [], ["Missing"])
    except AutomationError as exc:
        assert "Unknown site group" in str(exc)
    else:
        raise AssertionError("unknown tag was accepted")


def test_secret_round_trip_does_not_keep_the_password_in_the_stored_text():
    key = bytes.fromhex("11" * 32)
    stored = encrypt_secret(key, PASSWORD)
    assert PASSWORD not in stored
    assert decrypt_secret(key, stored) == PASSWORD


def test_ssl_port_is_preferred_and_plaintext_is_the_fallback(monkeypatch):
    from easy_radius.routeros_api import connect_router

    calls = []

    class Dummy:
        def close(self):
            pass

    def fake_connect(**kwargs):
        calls.append(kwargs)
        if kwargs["port"] == 8729 and len(calls) == 1:
            raise OSError("connection refused")
        return Dummy()

    monkeypatch.setattr("librouteros.connect", fake_connect)
    session = connect_router("192.0.2.10", "radius-auto", PASSWORD, allow_plaintext=True)
    assert session.port == 8728
    assert calls[0]["port"] == 8729
    assert calls[0]["ssl_wrapper"] is not None
    assert calls[1]["port"] == 8728
    assert calls[1].get("ssl_wrapper") is None

    calls.clear()

    def ssl_ok(**kwargs):
        calls.append(kwargs)
        return Dummy()

    monkeypatch.setattr("librouteros.connect", ssl_ok)
    assert connect_router("192.0.2.10", "radius-auto", PASSWORD).port == 8729
    assert len(calls) == 1

    calls.clear()

    def refuse(**kwargs):
        calls.append(kwargs["port"])
        raise OSError("closed")

    monkeypatch.setattr("librouteros.connect", refuse)
    try:
        connect_router("192.0.2.10", "radius-auto", PASSWORD)
    except Exception:
        pass
    assert calls == [8729]

    def both_fail(**kwargs):
        raise OSError(f"bad {kwargs['password']}")

    monkeypatch.setattr("librouteros.connect", both_fail)
    try:
        connect_router("192.0.2.10", "radius-auto", PASSWORD)
    except AutomationError as exc:
        assert PASSWORD not in str(exc)
    else:
        raise AssertionError("connection failure was ignored")


def _app(tmp_path, fakes):
    data = tmp_path / "data"
    prepare_state(data, admin_password=PASSWORD)
    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True

    def connector(host, username, password):
        assert password == PASSWORD
        assert username == "radius-auto"
        return fakes[host]

    app.config["ROUTER_CONNECT"] = connector
    client = app.test_client()
    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    logged = client.post("/login", data={"username": "neill", "password": PASSWORD, "csrf_token": token})
    assert logged.status_code == 302
    state = load_state(data)
    state["routers"] = [
        {
            "id": "r1",
            "site_name": "ExampleSite",
            "ip": "192.0.2.10",
            "secret": "example-router-secret",
            "enabled": True,
            "tags": ["North"],
            "client_name": "examplesite",
        },
        {
            "id": "r2",
            "site_name": "Example North",
            "ip": "192.0.2.11",
            "secret": "example-router-secret",
            "enabled": True,
            "tags": ["North"],
            "client_name": "example_north",
        },
        {
            "id": "r3",
            "site_name": "Example South",
            "ip": "192.0.2.12",
            "secret": "example-router-secret",
            "enabled": True,
            "tags": [],
            "client_name": "example_south",
        },
    ]
    from easy_radius.store import save_state

    save_state(data, state)
    return app, client, data


def _save_account(client, data):
    page = client.get("/automation")
    body = page.get_data(as_text=True)
    assert "Set NTP" in body
    assert "Set DNS" in body
    token = _csrf(body)
    saved = client.post(
        "/automation/account",
        data={"csrf_token": token, "username": "radius-auto", "password": PASSWORD, "group": "write"},
        follow_redirects=True,
    )
    text = saved.get_data(as_text=True)
    assert "Service account saved" in text
    assert PASSWORD not in text
    raw = data_path(data).read_text(encoding="utf-8")
    assert PASSWORD not in raw
    state = load_state(data)
    assert account_password(state) == ("radius-auto", PASSWORD)
    return _csrf(text)


def test_check_writes_nothing_and_run_is_idempotent(tmp_path):
    fakes = {
        "192.0.2.10": FakeRouter({"/ip/dns": {"servers": "192.0.2.1", "allow-remote-requests": "false"}}),
    }
    _app_obj, client, data = _app(tmp_path, fakes)
    token = _save_account(client, data)
    blocked = client.post(
        "/automation/tasks/builtin-dns/run",
        data={"csrf_token": token, "router_ids": ["r1", "r2"], "mode": "check"},
        follow_redirects=True,
    )
    assert "more than one router" in blocked.get_data(as_text=True)
    token = _csrf(blocked.get_data(as_text=True))
    checked = client.post(
        "/automation/tasks/builtin-dns/run",
        data={"csrf_token": token, "router_ids": "r1", "mode": "check", "batch": "1"},
        follow_redirects=True,
    )
    body = checked.get_data(as_text=True)
    assert "would change" in body
    assert "192.0.2.1" in body
    assert "192.0.2.53,192.0.2.54" in body
    assert "Dry run: nothing was written." in body
    assert [event for event in fakes["192.0.2.10"].events if event[0] != "close"] == [("get", "/ip/dns")]
    before = len(fakes["192.0.2.10"].events)
    token = _csrf(body)
    ran = client.post(
        "/automation/tasks/builtin-dns/run",
        data={"csrf_token": token, "router_ids": "r1", "mode": "run", "batch": "1"},
        follow_redirects=True,
    )
    ran_body = ran.get_data(as_text=True)
    assert "changed" in ran_body
    assert "View /export" in ran_body
    router = fakes["192.0.2.10"]
    assert router.events[before][0] == "export"
    assert router.events.index(("export",), before) < next(
        i for i, event in enumerate(router.events) if event[0] == "set"
    )
    assert ("set", "/ip/dns", {"servers": "192.0.2.53,192.0.2.54"}) in [
        event for event in router.events if event[0] == "set"
    ]
    exports = list((data / "automation" / "runs").glob("*/*.rsc"))
    assert exports
    assert PASSWORD not in exports[0].read_text(encoding="utf-8")
    token = _csrf(ran_body)
    again = client.post(
        "/automation/tasks/builtin-dns/run",
        data={"csrf_token": token, "router_ids": "r1", "mode": "run", "batch": "1"},
        follow_redirects=True,
    )
    assert ">ok<" in again.get_data(as_text=True) or "ok" in again.get_data(as_text=True)
    assert [event for event in router.events if event[0] == "set"] == [
        ("set", "/ip/dns", {"servers": "192.0.2.53,192.0.2.54"})
    ]
    state = load_state(data)
    audit = " ".join(event["detail"] for event in state["audit"])
    assert "neill" == state["audit"][-1]["actor"]
    assert "Set DNS" in audit
    assert PASSWORD not in audit
    history = client.get("/history")
    assert "ExampleSite" in history.get_data(as_text=True)
    guest = _app_obj.test_client()
    assert guest.get("/automation").status_code == 302


def test_failure_stops_the_next_batch(tmp_path):
    fakes = {
        "192.0.2.10": FakeRouter({"/system/identity": {"name": "old"}}),
        "192.0.2.11": FakeRouter({"/system/identity": {"name": "old"}}, fail=True),
        "192.0.2.12": FakeRouter({"/system/identity": {"name": "old"}}),
    }
    _app_obj, client, data = _app(tmp_path, fakes)
    token = _save_account(client, data)
    page = client.get("/automation/tasks/new")
    token = _csrf(page.get_data(as_text=True))
    created = client.post(
        "/automation/tasks/new",
        data={
            "csrf_token": token,
            "name": "Set identity",
            "body": "name: Set identity\nsteps:\n  - path: /system/identity\n    set:\n      name: ExampleSite\n",
        },
        follow_redirects=True,
    )
    assert "Task saved" in created.get_data(as_text=True)
    state = load_state(data)
    task_id = next(task["id"] for task in state["tasks"] if task["name"] == "Set identity" and not task.get("builtin"))
    token = _csrf(created.get_data(as_text=True))
    ran = client.post(
        f"/automation/tasks/{task_id}/run",
        data={
            "csrf_token": token,
            "router_ids": ["r1", "r2", "r3"],
            "confirm_many": "yes",
            "mode": "run",
            "batch": "1",
        },
        follow_redirects=True,
    )
    body = ran.get_data(as_text=True)
    assert "write refused" in body
    assert "skipped" in body
    assert fakes["192.0.2.12"].events == []
    assert any(event[0] == "set" for event in fakes["192.0.2.10"].events)
    raw = json.dumps(load_state(data)["audit"])
    assert PASSWORD not in raw


def test_routeros_commands_are_checked_and_run_like_yaml(tmp_path):
    from easy_radius.automation import _apply_one
    from easy_radius.routeros_cli import CommandSyntaxError, parse_commands

    text = "\n".join(
        [
            "/ip dns set servers=192.0.2.53",
            "/system ntp client set enabled=yes",
            "/ip service set ftp address=192.0.2.0/24",
            '/ip service set [find where name="ftp"] address=192.0.2.10/32',
            "/ip service disable telnet",
            "/ip service enable api-ssl",
            "/ip firewall filter add chain=input action=accept",
            "/ip firewall filter remove [find comment=example]",
            "/system identity set name={{ identity_name }}",
        ]
    )
    commands, warnings = parse_commands(text)
    assert warnings == []
    assert [(item.path, item.verb) for item in commands[:3]] == [
        ("/ip/dns", "set"),
        ("/system/ntp/client", "set"),
        ("/ip/service", "set"),
    ]
    assert commands[2].where == {"name": "ftp"}
    assert commands[2].values["address"] == "192.0.2.0/24"
    assert commands[3].where == {"name": "ftp"}
    assert commands[5].verb == "enable" and commands[5].where == {"name": "api-ssl"}
    assert commands[8].values["name"] == "{{ identity_name }}"
    parsed = parse_template(text)
    assert parsed.steps[6].verb == "add"
    assert parsed.steps[6].path == "/ip/firewall/filter"

    try:
        parse_commands(
            "/ip dns set servers=192.0.2.53\n"
            "not a command\n"
            "/ip service set [find name=ftp\n"
            '/ip dns set servers="192.0.2.53\n'
        )
    except CommandSyntaxError as exc:
        message = str(exc)
        assert "Line 2:" in message
        assert "Line 3: brackets were not closed" in message
        assert "Line 4: a quoted value was not closed" in message
    else:
        raise AssertionError("invalid commands were accepted")
    try:
        parse_commands("/ip service set where name=ftp address=192.0.2.0/24\n")
    except CommandSyntaxError as exc:
        assert "find where" in str(exc)
    else:
        raise AssertionError("a bare where was accepted")

    _unknown, notes = parse_commands("/made/up set foo=1\n")
    assert any("unknown path /made/up" in note for note in notes)

    class Rows:
        def __init__(self):
            self.rows_data = {
                "/ip/service": [
                    {"name": "telnet", "disabled": "false", ".id": "*2"},
                    {"name": "api-ssl", "disabled": "true", ".id": "*4"},
                ],
                "/ip/firewall/filter": [{"comment": "example", ".id": "*3"}],
            }
            self.events = []

        def rows(self, path):
            return [dict(row) for row in self.rows_data.get(path, [])]

        def get(self, path):
            found = self.rows(path)
            row = dict(found[0]) if found else {}
            row.pop(".id", None)
            return {str(key): str(value) for key, value in row.items()}

        def set_matching(self, path, where, values):
            self.events.append(("set", path, dict(where), dict(values)))
            for row in self.rows_data.get(path, []):
                if all(str(row.get(key)) == value for key, value in where.items()):
                    row.update(values)

        def add(self, path, values):
            self.events.append(("add", path, dict(values)))
            self.rows_data.setdefault(path, []).append(dict(values))

        def remove(self, path, where):
            self.events.append(("remove", path, dict(where)))
            self.rows_data[path] = [
                row
                for row in self.rows_data.get(path, [])
                if not all(str(row.get(key)) == value for key, value in where.items())
            ]

        def export(self):
            return "# export\n"

        def close(self):
            pass

    router = {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10"}
    body = "\n".join(
        [
            "/ip service disable telnet",
            "/ip firewall filter add chain=input action=accept",
            "/ip firewall filter remove [find comment=example]",
        ]
    )
    session = Rows()
    dry = _apply_one(session, parse_template(body), {}, True, tmp_path, "20260101T000000Z", router)
    assert dry["status"] == "changed"
    assert "Dry run: nothing was written." in dry["output"]
    assert session.events == []
    ran = _apply_one(session, parse_template(body), {}, False, tmp_path, "20260101T000000Z", router)
    assert ran["status"] == "changed"
    assert ("set", "/ip/service", {"name": "telnet"}, {"disabled": "yes"}) in session.events
    assert ("add", "/ip/firewall/filter", {"chain": "input", "action": "accept"}) in session.events
    assert ("remove", "/ip/firewall/filter", {"comment": "example"}) in session.events
    again = _apply_one(session, parse_template(body), {}, False, tmp_path, "20260101T000001Z", router)
    assert again["status"] == "ok"

    fakes = {
        "192.0.2.10": FakeRouter({"/ip/dns": {"servers": "192.0.2.1", "allow-remote-requests": "false"}}),
    }
    _app_obj, client, data = _app(tmp_path / "web", fakes)
    token = _save_account(client, data)
    page = client.get("/automation/tasks/new")
    token = _csrf(page.get_data(as_text=True))
    rejected = client.post(
        "/automation/tasks/new",
        data={"csrf_token": token, "name": "Broken", "commands": "/ip dns print\n", "body": ""},
    )
    assert rejected.status_code == 400
    assert "Line 1:" in rejected.get_data(as_text=True)
    assert not any(task["name"] == "Broken" for task in load_state(data)["tasks"])
    token = _csrf(rejected.get_data(as_text=True))
    both = client.post(
        "/automation/tasks/new",
        data={
            "csrf_token": token,
            "name": "Both",
            "commands": "/ip dns set servers=192.0.2.53\n",
            "body": "name: Both\nsteps:\n  - path: /ip/dns\n    set:\n      servers: 192.0.2.1\n",
        },
    )
    assert both.status_code == 400
    assert "not both" in both.get_data(as_text=True)
    token = _csrf(both.get_data(as_text=True))
    warned = client.post(
        "/automation/tasks/new",
        data={"csrf_token": token, "name": "Odd path", "commands": "/made/up set foo=1\n", "body": ""},
        follow_redirects=True,
    )
    assert "unknown path /made/up" in warned.get_data(as_text=True)
    token = _csrf(warned.get_data(as_text=True))
    created = client.post(
        "/automation/tasks/new",
        data={
            "csrf_token": token,
            "name": "Set DNS from commands",
            "commands": "/ip dns set servers=192.0.2.53\n",
            "body": "",
        },
        follow_redirects=True,
    )
    assert "Task saved" in created.get_data(as_text=True)
    state = load_state(data)
    task = next(item for item in state["tasks"] if item["name"] == "Set DNS from commands")
    edit = client.get(f"/automation/tasks/{task['id']}/edit")
    edit_body = edit.get_data(as_text=True)
    assert "/ip dns set servers=192.0.2.53" in edit_body
    token = _csrf(created.get_data(as_text=True))
    checked = client.post(
        f"/automation/tasks/{task['id']}/run",
        data={"csrf_token": token, "router_ids": "r1", "mode": "check", "batch": "1"},
        follow_redirects=True,
    )
    assert "Dry run: nothing was written." in checked.get_data(as_text=True)
    assert [event for event in fakes["192.0.2.10"].events if event[0] != "close"] == [("get", "/ip/dns")]
    token = _csrf(checked.get_data(as_text=True))
    ran_page = client.post(
        f"/automation/tasks/{task['id']}/run",
        data={"csrf_token": token, "router_ids": "r1", "mode": "run", "batch": "1"},
        follow_redirects=True,
    )
    assert "changed" in ran_page.get_data(as_text=True)
    assert ("set", "/ip/dns", {"servers": "192.0.2.53"}) in fakes["192.0.2.10"].events
