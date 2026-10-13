"""RADIUS user passwords are stored and written only as SHA-512 crypt."""

import json

from easy_radius.backup import apply_payload, decrypt_backup, encrypt_backup, export_payload
from easy_radius.configgen import parse_users_file, render_users_file, rewrite_cleartext_passwords
from easy_radius.snapshots import load_snapshot, save_snapshot
from easy_radius.store import data_path, load_state, prepare_state, save_state, upgrade_password_storage
from easy_radius.userhash import hash_user_password, is_sha512_crypt
from easy_radius.web import create_app


KNOWN = (
    "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/"
    "O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
)


def _csrf(html: str) -> str:
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def test_sha512_crypt_matches_the_published_vector():
    assert hash_user_password("Hello world!", salt="saltstring") == KNOWN
    assert is_sha512_crypt(KNOWN)


def test_sha512_crypt_matches_glibc():
    import crypt

    stored = hash_user_password("example-password")
    assert crypt.crypt("example-password", stored) == stored
    assert crypt.crypt("example-password-99", stored) != stored


def test_startup_hashes_plaintext_users_snapshots_and_backups(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    state = {
        "routers": [
            {
                "id": "r1",
                "site_name": "ExampleSite",
                "ip": "192.0.2.10",
                "secret": "example-router-secret",
                "enabled": True,
            }
        ],
        "users": [
            {
                "id": "u1",
                "username": "alice",
                "password": "example-password",
                "group": "write",
                "enabled": True,
            }
        ],
        "audit": [{"at": "2026-01-01T00:00:00Z", "actor": "neill", "action": "user.add", "detail": "Added alice"}],
    }
    (data / "data.json").write_text(json.dumps(state), encoding="utf-8")
    snap_dir = data / "snapshots"
    snap_dir.mkdir()
    (snap_dir / "20260101T000000Z.json").write_text(
        json.dumps({"id": "20260101T000000Z", "routers": state["routers"], "users": state["users"]}),
        encoding="utf-8",
    )
    backup_users = data / "backups" / "20260101T000000Z" / "users"
    backup_users.parent.mkdir(parents=True)
    backup_users.write_text(
        'alice Cleartext-Password := "example-password"\n    Mikrotik-Group = "write"\n',
        encoding="utf-8",
    )

    prepare_state(data, admin_password="example-password")
    raw = (data / "data.json").read_text(encoding="utf-8")
    saved = json.loads(raw)
    assert is_sha512_crypt(saved["users"][0]["password"])
    assert saved["users"][0]["nt_password"] == "BB7FAFD45FABBDBD035ECD5A7A78C01D"
    assert "example-password" not in raw
    assert saved["routers"][0]["secret"] == "example-router-secret"
    assert saved["audit"][0]["detail"] == "Added alice"

    snap_raw = (snap_dir / "20260101T000000Z.json").read_text(encoding="utf-8")
    assert "example-password" not in snap_raw
    loaded = load_snapshot(data, "20260101T000000Z")
    assert is_sha512_crypt(loaded["users"][0]["password"])

    users_raw = backup_users.read_text(encoding="utf-8")
    assert "Cleartext-Password" not in users_raw
    assert "example-password" not in users_raw
    parsed = parse_users_file(users_raw)
    assert is_sha512_crypt(parsed[0]["password"])
    assert parsed[0]["nt_password"] == "BB7FAFD45FABBDBD035ECD5A7A78C01D"
    assert "NT-Password := 0xBB7FAFD45FABBDBD035ECD5A7A78C01D" in users_raw
    import crypt

    assert crypt.crypt("example-password", parsed[0]["password"]) == parsed[0]["password"]


def test_backup_and_new_snapshot_do_not_keep_plaintext(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password="example-password")
    state = load_state(data)
    state["users"] = [
        {"id": "u1", "username": "alice", "password": "example-password", "group": "write", "enabled": True}
    ]
    state["routers"] = [
        {"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "secret": "example-router-secret", "enabled": True}
    ]
    save_state(data, state)
    raw = data_path(data).read_text(encoding="utf-8")
    assert "example-password" not in raw
    assert state["routers"][0]["secret"] == "example-router-secret"

    payload = export_payload(load_state(data))
    blob = encrypt_backup(payload, "example-passphrase", iterations=1000)
    restored = decrypt_backup(blob, "example-passphrase")
    assert "example-password" not in json.dumps(restored)
    assert is_sha512_crypt(restored["users"][0]["password"])
    assert restored["routers"][0]["secret"] == "example-router-secret"

    incoming = {
        "version": 1,
        "routers": state["routers"],
        "users": [{"id": "u2", "username": "bob", "password": "example-password", "group": "read"}],
        "admin_password_hash": "",
    }
    apply_payload(state, incoming)
    assert is_sha512_crypt(state["users"][0]["password"])
    save_state(data, state)
    assert "example-password" not in data_path(data).read_text(encoding="utf-8")

    # A snapshot taken from plaintext in memory is hashed before it hits disk.
    state["users"][0]["password"] = "example-password"
    snap_id = save_snapshot(data, state)
    snap_text = (data / "snapshots" / f"{snap_id}.json").read_text(encoding="utf-8")
    assert "example-password" not in snap_text
    assert is_sha512_crypt(load_snapshot(data, snap_id)["users"][0]["password"])


def test_rewrite_cleartext_users_file_is_idempotent():
    original = 'alice Cleartext-Password := "example-password"\n    Mikrotik-Group = "write"\n'
    once = rewrite_cleartext_passwords(original)
    twice = rewrite_cleartext_passwords(once)
    assert once == twice
    assert "Cleartext-Password" not in once
    rendered = render_users_file(parse_users_file(once))
    assert "Crypt-Password" in rendered


def test_ui_sets_a_new_password_without_showing_the_old_one(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password="example-password")
    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    client = app.test_client()
    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    client.post(
        "/login",
        data={"username": "neill", "password": "example-password", "csrf_token": token},
    )
    page = client.get("/users/new")
    token = _csrf(page.get_data(as_text=True))
    created = client.post(
        "/users/new",
        data={
            "csrf_token": token,
            "username": "alice",
            "password": "example-password",
            "group": "write",
            "access": "all",
        },
        follow_redirects=True,
    )
    body = created.get_data(as_text=True)
    assert "Set new password" in body
    assert "Show" not in body
    assert "example-password" not in body
    saved = load_state(data)
    first = saved["users"][0]["password"]
    assert is_sha512_crypt(first)
    assert "example-password" not in data_path(data).read_text(encoding="utf-8")
    assert saved["audit"][-1]["detail"] == "Added alice (write, All routers)"

    edit = client.get(f"/users/{saved['users'][0]['id']}/edit")
    edit_body = edit.get_data(as_text=True)
    assert "Set new password" in edit_body
    assert first not in edit_body
    assert "example-password" not in edit_body
    token = _csrf(edit_body)
    kept = client.post(
        f"/users/{saved['users'][0]['id']}/edit",
        data={
            "csrf_token": token,
            "username": "alice",
            "password": "",
            "group": "read",
            "access": "all",
        },
        follow_redirects=True,
    )
    assert kept.status_code == 200
    assert load_state(data)["users"][0]["password"] == first
    assert load_state(data)["users"][0]["group"] == "read"

    page = client.get(f"/users/{saved['users'][0]['id']}/edit")
    token = _csrf(page.get_data(as_text=True))
    client.post(
        f"/users/{saved['users'][0]['id']}/edit",
        data={
            "csrf_token": token,
            "username": "alice",
            "password": "example-password-99",
            "group": "read",
            "access": "all",
        },
        follow_redirects=True,
    )
    changed = load_state(data)["users"][0]["password"]
    assert changed != first
    assert is_sha512_crypt(changed)
    raw = data_path(data).read_text(encoding="utf-8")
    assert "example-password" not in raw
    assert "example-password-99" not in raw
    assert all("password" not in event["detail"].lower() for event in load_state(data)["audit"])


def test_nt_hash_matches_the_known_password_vector():
    from easy_radius.userhash import nt_hash

    assert nt_hash("password") == "8846F7EAEE8FB117AD06BDD830B7586C"
    assert nt_hash("example-password") == "BB7FAFD45FABBDBD035ECD5A7A78C01D"


def test_users_file_writes_crypt_and_nt_as_check_items():
    from easy_radius.userhash import hash_user_password, nt_hash

    crypt = hash_user_password("example-password", salt="examplesalt1234")
    nt = nt_hash("example-password")
    text = render_users_file(
        [{"username": "alice", "password": crypt, "nt_password": nt, "group": "write"}],
    )
    assert f'alice Crypt-Password := "{crypt}", NT-Password := 0x{nt}' in text
    assert "Cleartext-Password" not in text
    assert "example-password" not in text
    parsed = parse_users_file(text)[0]
    assert parsed["password"] == crypt
    assert parsed["nt_password"] == nt


def test_crypt_only_user_keeps_pap_and_shows_the_winbox_badge(tmp_path):
    from easy_radius.userhash import hash_user_password, is_nt_hash, is_sha512_crypt, needs_mschap_password

    data = tmp_path / "data"
    prepare_state(data, admin_password="example-password")
    state = load_state(data)
    crypt = hash_user_password("example-password", salt="examplesalt1234")
    state["users"] = [
        {
            "id": "u1",
            "username": "alice",
            "password": crypt,
            "group": "write",
            "enabled": True,
            "access": "all",
            "router_ids": [],
            "access_tags": [],
        }
    ]
    save_state(data, state)
    saved = load_state(data)
    assert needs_mschap_password(saved["users"][0])
    assert not is_nt_hash(str(saved["users"][0].get("nt_password") or ""))
    text = render_users_file(saved["users"])
    assert "Crypt-Password" in text
    assert "NT-Password" not in text

    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    client = app.test_client()
    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    client.post("/login", data={"username": "neill", "password": "example-password", "csrf_token": token})
    body = client.get("/users").get_data(as_text=True)
    assert "Set password again to enable Winbox/MS-CHAP" in body
    assert crypt not in body
    edit = client.get("/users/u1/edit")
    edit_body = edit.get_data(as_text=True)
    assert "Set password again to enable Winbox/MS-CHAP" in edit_body
    token = _csrf(edit_body)
    client.post(
        "/users/u1/edit",
        data={
            "csrf_token": token,
            "username": "alice",
            "password": "example-password-99",
            "group": "write",
            "access": "all",
        },
        follow_redirects=True,
    )
    updated = load_state(data)["users"][0]
    raw = data_path(data).read_text(encoding="utf-8")
    assert is_sha512_crypt(updated["password"])
    assert updated["password"] != crypt
    assert is_nt_hash(updated["nt_password"])
    assert "example-password" not in raw
    assert "example-password-99" not in raw
    assert not needs_mschap_password(updated)
    again = client.get("/users").get_data(as_text=True)
    assert "Set password again to enable Winbox/MS-CHAP" not in again


def test_routers_page_explains_src_address(tmp_path):
    data = tmp_path / "data"
    prepare_state(data, admin_password="example-password")
    state = load_state(data)
    state["radius_server_address"] = "192.0.2.1"
    state["routers"] = [
        {
            "id": "r1",
            "site_name": "ExampleSite",
            "ip": "192.0.2.10",
            "secret": "example-router-secret",
            "enabled": True,
            "tags": [],
            "client_name": "examplesite_192_0_2_10",
        }
    ]
    save_state(data, state)
    app = create_app(data_dir=data, runner=lambda args, timeout=120: None)
    app.config["TESTING"] = True
    client = app.test_client()
    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    client.post("/login", data={"username": "neill", "password": "example-password", "csrf_token": token})
    routers = client.get("/routers")
    body = routers.get_data(as_text=True)
    assert "src-address=192.0.2.10" in body
    assert "timeout=3s" in body
    assert "/radius set [find address=192.0.2.1]" in body
    assert "NAT" in body
    assert "example-router-secret" in body
