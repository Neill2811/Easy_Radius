import re

from easy_radius.hostcmd import CommandResult
from easy_radius.store import prepare_state
from easy_radius.web import create_app


class FakeRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, args, timeout=120):
        self.calls.append(list(args))
        if len(args) >= 2 and args[-2:] == ["freeradius", "-XC"]:
            return CommandResult(list(args), 0, "Configuration appears to be OK.\n", "")
        if args[:3] == ["systemctl", "is-active", "freeradius"]:
            return CommandResult(list(args), 0, "active\n", "")
        if args and args[0] == "radtest":
            return CommandResult(list(args), 0, "Received Access-Accept Id 5 from 127.0.0.1:1812\n", "")
        return CommandResult(list(args), 0, "", "")


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def _app(tmp_path):
    data = tmp_path / "data"
    prepare_state(
        data,
        admin_password="example-password",
    )
    # Keep the localhost secret stable for assertions.
    from easy_radius.store import load_state, save_state

    state = load_state(data)
    state["localhost_secret"] = "example-localhost-secret"
    save_state(data, state)
    runner = FakeRunner()
    app = create_app(data_dir=data, runner=runner)
    app.config["TESTING"] = True
    app.config["CLIENTS_CONF"] = tmp_path / "clients.conf"
    app.config["USERS_FILE"] = tmp_path / "authorize"
    app.config["POLICY_FILE"] = tmp_path / "policy" / "easy_radius"
    app.config["AUTH_LOG"] = tmp_path / "auth.log"
    app.config["ACCT_LOG"] = tmp_path / "acct.log"
    return app, runner


def test_login_csrf_and_router_user_flow(tmp_path):
    app, runner = _app(tmp_path)
    client = app.test_client()

    blocked = client.get("/routers")
    assert blocked.status_code == 302
    assert "/login" in blocked.headers["Location"]

    page = client.get("/login")
    assert "Easy" in page.get_data(as_text=True)
    bad = client.post(
        "/login",
        data={"username": "neill", "password": "example-password"},
    )
    assert bad.status_code == 400

    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    wrong = client.post(
        "/login",
        data={"username": "neill", "password": "nope", "csrf_token": token},
    )
    assert wrong.status_code == 401

    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    logged_in = client.post(
        "/login",
        data={"username": "neill", "password": "example-password", "csrf_token": token},
    )
    assert logged_in.status_code == 302

    routers = client.get("/routers")
    token = _csrf(routers.get_data(as_text=True))
    created = client.post(
        "/routers/new",
        data={
            "csrf_token": token,
            "site_name": "ExampleSite",
            "ip": "192.0.2.10",
            "secret": "example-router-secret",
        },
        follow_redirects=True,
    )
    body = created.get_data(as_text=True)
    assert "ExampleSite" in body
    assert "192.0.2.10" in body
    assert "example-router-secret" in body
    assert "••••••••" in body

    users = client.get("/users")
    token = _csrf(users.get_data(as_text=True))
    created_user = client.post(
        "/users/new",
        data={
            "csrf_token": token,
            "username": "alice",
            "password": "example-password",
            "group": "write",
        },
        follow_redirects=True,
    )
    user_body = created_user.get_data(as_text=True)
    assert "alice" in user_body
    assert "write" in user_body
    assert "Set new password" in user_body
    assert "example-password" not in user_body

    apply_page = client.get("/apply")
    token = _csrf(apply_page.get_data(as_text=True))
    applied = client.post("/apply", data={"csrf_token": token}, follow_redirects=True)
    apply_body = applied.get_data(as_text=True)
    assert "Configuration appears to be OK." in apply_body
    assert "restarted" in apply_body.lower() or "Check passed" in apply_body
    clients_text = (tmp_path / "clients.conf").read_text(encoding="utf-8")
    assert "example-router-secret" in clients_text
    assert "example-localhost-secret" in clients_text
    users_text = (tmp_path / "authorize").read_text(encoding="utf-8")
    assert "Crypt-Password :=" in users_text
    assert "example-password" not in users_text
    assert "Cleartext-Password" not in users_text
    assert 'Mikrotik-Group = "write"' in users_text

    test_page = client.get("/test")
    token = _csrf(test_page.get_data(as_text=True))
    tested = client.post(
        "/test",
        data={"csrf_token": token, "username": "alice", "password": "example-password"},
        follow_redirects=True,
    )
    test_body = tested.get_data(as_text=True)
    assert "Access-Accept" in test_body
    assert "example-localhost-secret" not in test_body
    assert any(call[0] == "radtest" and call[-1] == "example-localhost-secret" for call in runner.calls)
