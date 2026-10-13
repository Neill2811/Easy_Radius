import json

import pytest

from easy_radius.store import check_admin_password, data_path, load_state, prepare_state, save_state
from easy_radius.web import create_app


def _csrf(html: str) -> str:
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def _client(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password="example-password")
    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    client = app.test_client()
    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    logged = client.post(
        "/login",
        data={"username": "neill", "password": "example-password", "csrf_token": token},
    )
    assert logged.status_code == 302
    return app, client, data


def test_change_password_stores_a_hash_and_signs_out_other_sessions(tmp_path):
    app, client, data = _client(tmp_path)
    other = app.test_client()
    cookie = client.get_cookie("session")
    assert cookie is not None
    other.set_cookie("session", cookie.value)
    assert other.get("/routers").status_code == 200

    page = client.get("/security")
    body = page.get_data(as_text=True)
    assert "Change password" in body
    token = _csrf(body)
    old_key = load_state(data)["secret_key"]
    changed = client.post(
        "/security/password",
        data={
            "csrf_token": token,
            "current_password": "example-password",
            "new_password": "example-password-99",
            "confirm_password": "example-password-99",
        },
        follow_redirects=True,
    )
    assert "Password changed" in changed.get_data(as_text=True)
    saved = json.loads(data_path(data).read_text(encoding="utf-8"))
    assert "example-password-99" not in data_path(data).read_text(encoding="utf-8")
    assert check_admin_password(saved, "neill", "example-password-99")
    assert not check_admin_password(saved, "neill", "example-password")
    assert saved["secret_key"] != old_key
    assert any(event["detail"] == "Changed the admin password" for event in saved["audit"])
    assert other.get("/routers").status_code == 302
    assert client.get("/routers").status_code == 200


def test_change_password_rejects_a_short_or_wrong_password(tmp_path):
    _app, client, data = _client(tmp_path)
    page = client.get("/security")
    token = _csrf(page.get_data(as_text=True))
    short = client.post(
        "/security/password",
        data={
            "csrf_token": token,
            "current_password": "example-password",
            "new_password": "short-pass",
            "confirm_password": "short-pass",
        },
        follow_redirects=True,
    )
    assert "at least 12 characters" in short.get_data(as_text=True)
    page = client.get("/security")
    token = _csrf(page.get_data(as_text=True))
    wrong = client.post(
        "/security/password",
        data={
            "csrf_token": token,
            "current_password": "not-the-password",
            "new_password": "example-password-99",
            "confirm_password": "example-password-99",
        },
        follow_redirects=True,
    )
    assert "not correct" in wrong.get_data(as_text=True)
    assert check_admin_password(load_state(data), "neill", "example-password")


def test_reset_command_updates_the_hash(tmp_path, monkeypatch):
    from easy_radius.reset_admin_password import main
    from easy_radius.store import initial_password_path

    data = tmp_path / "data"
    prepare_state(data, admin_password="example-password")
    initial_password_path(data).write_text("example-password\n", encoding="utf-8")
    answers = iter(["example-password-99", "example-password-99"])
    monkeypatch.setenv("RADIUS_ADMIN_DATA_DIR", str(data))
    monkeypatch.setattr("easy_radius.reset_admin_password.getpass.getpass", lambda prompt="": next(answers))
    assert main([]) == 0
    saved = load_state(data)
    assert check_admin_password(saved, "neill", "example-password-99")
    raw = data_path(data).read_text(encoding="utf-8")
    assert "example-password-99" not in raw
    assert not initial_password_path(data).exists()
    mismatch = iter(["example-password-99", "example-password-98"])
    monkeypatch.setattr("easy_radius.reset_admin_password.getpass.getpass", lambda prompt="": next(mismatch))
    assert main([]) == 1


def test_reset_command_rejects_arguments():
    from easy_radius.reset_admin_password import main

    assert main(["example-password-99"]) == 2
