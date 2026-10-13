import json
import os

from easy_radius.store import (
    check_admin_password,
    data_path,
    initial_password_path,
    prepare_state,
    verify_password,
)


def test_admin_password_is_hashed_and_printed_once(tmp_path, capsys):
    state = prepare_state(tmp_path)
    printed = capsys.readouterr().out
    password = next(
        line.split(": ", 1)[1] for line in printed.splitlines() if line.startswith("Password:")
    )
    raw = data_path(tmp_path).read_text(encoding="utf-8")
    assert password not in raw
    assert verify_password(password, state["admin_password_hash"])
    assert check_admin_password(state, "neill", password)
    assert not check_admin_password(state, "neill", "example-password")
    assert not check_admin_password(state, "other", password)
    assert (os.stat(data_path(tmp_path)).st_mode & 0o777) == 0o600
    assert password in initial_password_path(tmp_path).read_text(encoding="utf-8")
    assert (os.stat(initial_password_path(tmp_path)).st_mode & 0o777) == 0o600

    prepare_state(tmp_path)
    assert "Password:" not in capsys.readouterr().out
    again = json.loads(data_path(tmp_path).read_text(encoding="utf-8"))
    assert again["admin_password_hash"] == state["admin_password_hash"]
    assert again["secret_key"] == state["secret_key"]
    assert again["localhost_secret"] == state["localhost_secret"]


def test_install_bootstrap_does_not_create_admin_password(tmp_path, capsys):
    state = prepare_state(tmp_path, ensure_admin=False)
    assert state["localhost_secret"]
    assert state["secret_key"]
    assert state["admin_password_hash"] == ""
    assert "Password:" not in capsys.readouterr().out
    assert not initial_password_path(tmp_path).exists()
