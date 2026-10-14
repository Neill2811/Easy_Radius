import json
import os
import re
import subprocess
from pathlib import Path

from easy_radius.backup import decrypt_backup, encrypt_backup
from easy_radius.configgen import render_clients_conf, render_users_file
from easy_radius.freeradius_site import configure, patch_site
from easy_radius.logs import (
    filter_auth,
    parse_acct_log,
    parse_auth_log,
    router_health,
    session_view,
)
from easy_radius.mikrotik import mikrotik_commands
from easy_radius.snapshots import list_snapshots, load_snapshot, save_snapshot
from easy_radius.totp import totp_at, verify_totp

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
SITE = """server default {
\tauthorize {
\t\tfiles
\t}
\taccounting {
\t\tdetail
\t}
\tpost-auth {
\t\tupdate {
\t\t\t&reply += &session-state:
\t\t}
\t\tPost-Auth-Type REJECT {
\t\t\tattr_filter.access_reject
\t\t}
\t}
}
"""


def test_disabled_entries_are_omitted_from_generated_files():
    routers = [
        {
            "site_name": "ExampleSite",
            "ip": "192.0.2.10",
            "secret": "example-router-secret",
            "client_name": "examplesite_192_0_2_10",
            "enabled": False,
        },
        {
            "site_name": "Example North",
            "ip": "192.0.2.11",
            "secret": "example-north-secret",
            "client_name": "example_north_192_0_2_11",
            "enabled": True,
        },
    ]
    users = [
        {"username": "alice", "password": "example-password", "group": "write", "enabled": False},
        {"username": "bob", "password": "example-password", "group": "read", "enabled": True},
    ]
    clients = render_clients_conf("example-localhost-secret", routers)
    written_users = render_users_file(users)
    assert "example-router-secret" not in clients
    assert "example-north-secret" in clients
    assert "alice" not in written_users
    assert "bob" in written_users
    assert "Crypt-Password" in written_users
    assert "example-password" not in written_users
    assert 'Mikrotik-Group = "read"' in written_users


def test_mikrotik_commands_set_src_address_to_the_router_ip():
    text = mikrotik_commands("192.0.2.1", "example-router-secret", "192.0.2.10")
    assert text == (
        "/radius add address=192.0.2.1 secret=example-router-secret service=login "
        "src-address=192.0.2.10 timeout=3s\n"
        "/radius set [find address=192.0.2.1] src-address=192.0.2.10 secret=example-router-secret\n"
        "/user aaa set use-radius=yes\n"
        ":if ([:len [/certificate find name=api-ssl-ca]] = 0) do={\n"
        "/certificate add name=api-ssl-ca common-name=api-ssl-ca "
        "key-usage=key-cert-sign,crl-sign days-valid=3650\n"
        "/certificate sign api-ssl-ca\n"
        ":delay 5\n"
        "}\n"
        ":if ([:len [/certificate find name=api-ssl]] = 0) do={\n"
        "/certificate add name=api-ssl common-name=192.0.2.10 days-valid=3650\n"
        "/certificate sign api-ssl ca=api-ssl-ca\n"
        ":delay 5\n"
        "}\n"
        "/ip service set api-ssl certificate=api-ssl address=192.0.2.1/32 disabled=no\n"
        "# Uncomment the next line if the input chain ends with a drop rule.\n"
        "# /ip firewall filter add chain=input protocol=tcp dst-port=8729 "
        'src-address=192.0.2.1 action=accept place-before=0 comment="Easy Radius API-SSL"\n'
    )
    assert "8728" not in text
    assert "ftp" not in text.lower()
    assert "snmp" not in text.lower()
    quoted = mikrotik_commands("192.0.2.1", 'has space "quote"', "192.0.2.10")
    assert 'secret="has space \\"quote\\""' in quoted
    v6 = mikrotik_commands("2001:db8::1", "example-router-secret", "2001:db8::10")
    assert 'address="2001:db8::1"' in v6
    assert 'src-address="2001:db8::10"' in v6
    assert 'common-name="2001:db8::10"' in v6
    assert 'address="2001:db8::1/128"' in v6


def test_auth_log_filters_and_ignores_junk():
    text = "\n".join(
        [
            "not a radius line",
            "EASYRADIUS auth time=100 result=Access-Accept user=alice nas=192.0.2.10",
            "EASYRADIUS auth time=200 result=Access-Reject user=bob nas=192.0.2.11",
            "EASYRADIUS auth time=300 result=Access-Accept user=alice nas=192.0.2.11",
        ]
    )
    events = parse_auth_log(text)
    assert [event["time"] for event in events] == [300, 200, 100]
    accept_alice = filter_auth(events, user="Ali", result="Access-Accept")
    assert [event["time"] for event in accept_alice] == [300, 100]
    one_router = filter_auth(events, nas="192.0.2.10")
    assert len(one_router) == 1
    assert one_router[0]["user"] == "alice"


def test_accounting_online_users_and_history():
    text = "\n".join(
        [
            "EASYRADIUS acct time=100 status=Start user=alice nas=192.0.2.10 session=s1",
            "EASYRADIUS acct time=130 status=Interim-Update user=alice nas=192.0.2.10 session=s1",
            "EASYRADIUS acct time=150 status=Start user=bob nas=192.0.2.11 session=s2",
            "EASYRADIUS acct time=200 status=Stop user=alice nas=192.0.2.10 session=s1",
            "noise",
        ]
    )
    online, history = session_view(parse_acct_log(text))
    assert [row["user"] for row in online] == ["bob"]
    assert history[0]["status"] == "Stop"
    assert len(history) == 4


def test_router_health_is_green_only_inside_the_window():
    routers = [
        {"id": "a", "ip": "192.0.2.10"},
        {"id": "b", "ip": "192.0.2.11"},
    ]
    rows = router_health(routers, [("192.0.2.10", 1_000), ("192.0.2.11", 100)], now=1_100, window=900)
    by_id = {row["id"]: row for row in rows}
    assert by_id["a"]["up"] is True
    assert by_id["b"]["up"] is False
    assert by_id["b"]["age"] == 1000


def test_totp_matches_rfc6238_vector():
    assert totp_at(RFC_SECRET, 59) == "287082"
    assert totp_at(RFC_SECRET, 1111111109) == "081804"
    assert verify_totp(RFC_SECRET, "287082", now=59)
    assert not verify_totp(RFC_SECRET, "000000", now=59)


def test_backup_round_trip_and_wrong_passphrase(tmp_path):
    payload = {
        "version": 1,
        "routers": [
            {
                "id": "r1",
                "site_name": "ExampleSite",
                "ip": "192.0.2.10",
                "secret": "example-router-secret",
                "enabled": True,
            }
        ],
        "users": [{"id": "u1", "username": "alice", "password": "example-password", "group": "write", "enabled": True}],
        "localhost_secret": "example-localhost-secret",
        "radius_server_address": "192.0.2.1",
        "audit": [],
        "totp_secret": "",
        "totp_enabled": False,
        "admin_password_hash": "pbkdf2_sha256$1$00$00",
    }
    blob = encrypt_backup(payload, "example-passphrase", iterations=1000)
    assert b"example-router-secret" not in blob
    restored = decrypt_backup(blob, "example-passphrase")
    assert restored["routers"][0]["secret"] == "example-router-secret"
    try:
        decrypt_backup(blob, "wrong-passphrase")
    except Exception as exc:
        assert "Passphrase" in str(exc)
    else:
        raise AssertionError("wrong passphrase was accepted")
    assert not (tmp_path / "unused").exists()


def test_snapshot_round_trip(tmp_path):
    state = {
        "routers": [{"id": "r1", "site_name": "ExampleSite", "ip": "192.0.2.10", "secret": "example-router-secret"}],
        "users": [{"id": "u1", "username": "alice", "password": "example-password", "group": "write"}],
    }
    snap_id = save_snapshot(tmp_path, state)
    state["routers"][0]["site_name"] = "Changed"
    loaded = load_snapshot(tmp_path, snap_id)
    assert loaded["routers"][0]["site_name"] == "ExampleSite"
    assert list_snapshots(tmp_path)[0]["routers"] == 1


def test_site_patch_is_idempotent(tmp_path):
    sites = tmp_path / "sites-enabled"
    sites.mkdir()
    (sites / "default").write_text(SITE, encoding="utf-8")
    assert configure(tmp_path) == "changed"
    text = (sites / "default").read_text(encoding="utf-8")
    assert "easy_radius_auth_accept" in text
    assert "easy_radius_auth_reject" in text
    assert "easy_radius_acct" in text
    assert text.count("easy_radius_acct") == 1
    assert "detail" in text
    module = (tmp_path / "mods-available" / "easy_radius").read_text(encoding="utf-8")
    assert "result=Access-Accept" in module
    assert "result=Access-Reject" in module
    assert "EASYRADIUS acct" in module
    assert configure(tmp_path) == "unchanged"
    assert (sites / "default").read_text(encoding="utf-8") == text
    patched, changed = patch_site(text)
    assert changed is False
    assert patched == text


def test_install_patches_site_without_touching_clients(tmp_path):
    root = Path(__file__).resolve().parents[1]
    freeradius = tmp_path / "freeradius"
    sites = freeradius / "sites-enabled"
    sites.mkdir(parents=True)
    (sites / "default").write_text(SITE, encoding="utf-8")
    original = "client keep_me {\n    secret = leave-this-secret\n}\n"
    (freeradius / "clients.conf").write_text(original, encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "EASY_RADIUS_APP_DIR": str(tmp_path / "app"),
            "EASY_RADIUS_FREERADIUS_DIR": str(freeradius),
            "EASY_RADIUS_BACKUP_ROOT": str(tmp_path / "backups"),
            "EASY_RADIUS_SKIP_PACKAGES": "1",
            "EASY_RADIUS_SKIP_DOCKER": "1",
            "SSH_CONNECTION": "",
            "SSH_CLIENT": "",
        }
    )
    result = subprocess.run(
        ["bash", str(root / "install.sh")],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert (freeradius / "clients.conf").read_text(encoding="utf-8") == original
    assert "easy_radius_auth_accept" in (sites / "default").read_text(encoding="utf-8")
    assert "Configured FreeRADIUS login and accounting logs." in result.stdout
    data = json.loads((tmp_path / "app" / "data" / "data.json").read_text(encoding="utf-8"))
    assert data["routers"] == []


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def _client(tmp_path):
    from easy_radius.hostcmd import CommandResult
    from easy_radius.store import load_state, prepare_state, save_state
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
            return CommandResult(list(args), 0, "", "")

    data = tmp_path / "data"
    prepare_state(data, admin_password="example-password")
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
    client = app.test_client()
    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    logged = client.post(
        "/login",
        data={"username": "neill", "password": "example-password", "csrf_token": token},
    )
    assert logged.status_code == 302
    return client, data


def test_disable_keeps_the_router_and_apply_omits_it(tmp_path):
    client, data = _client(tmp_path)
    page = client.get("/routers")
    token = _csrf(page.get_data(as_text=True))
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
    assert "Disable" in body
    assert "Delete" not in body
    router_id = json.loads((data / "data.json").read_text(encoding="utf-8"))["routers"][0]["id"]
    token = _csrf(body)
    client.post(
        f"/routers/{router_id}/enabled",
        data={"csrf_token": token, "enabled": "0"},
        follow_redirects=True,
    )
    page = client.get("/apply")
    token = _csrf(page.get_data(as_text=True))
    client.post("/apply", data={"csrf_token": token}, follow_redirects=True)
    written = (tmp_path / "clients.conf").read_text(encoding="utf-8")
    assert "example-router-secret" not in written
    saved = json.loads((data / "data.json").read_text(encoding="utf-8"))
    assert saved["routers"][0]["enabled"] is False
    assert any(event["action"] == "router.disable" for event in saved["audit"])


def test_rollback_restores_the_previous_apply(tmp_path):
    client, data = _client(tmp_path)

    def add(site, ip, secret):
        page = client.get("/routers/new")
        token = _csrf(page.get_data(as_text=True))
        client.post(
            "/routers/new",
            data={"csrf_token": token, "site_name": site, "ip": ip, "secret": secret},
        )

    add("ExampleSite", "192.0.2.10", "example-router-secret")
    page = client.get("/apply")
    token = _csrf(page.get_data(as_text=True))
    client.post("/apply", data={"csrf_token": token})
    add("Example North", "192.0.2.11", "example-north-secret")
    history = client.get("/history")
    body = history.get_data(as_text=True)
    assert "Added ExampleSite" in body
    token = _csrf(body)
    snap = re.search(r"/history/([0-9]{8}T[0-9]{6}Z(?:-[0-9]+)?)/rollback", body)
    assert snap
    client.post(f"/history/{snap.group(1)}/rollback", data={"csrf_token": token}, follow_redirects=True)
    saved = json.loads((data / "data.json").read_text(encoding="utf-8"))
    names = [router["site_name"] for router in saved["routers"]]
    assert names == ["ExampleSite"]
    written = (tmp_path / "clients.conf").read_text(encoding="utf-8")
    assert "example-router-secret" in written
    assert "example-north-secret" not in written


def test_backup_download_and_restore_round_trip(tmp_path):
    client, data = _client(tmp_path)
    page = client.get("/routers/new")
    token = _csrf(page.get_data(as_text=True))
    client.post(
        "/routers/new",
        data={
            "csrf_token": token,
            "site_name": "ExampleSite",
            "ip": "192.0.2.10",
            "secret": "example-router-secret",
        },
    )
    page = client.get("/backup")
    token = _csrf(page.get_data(as_text=True))
    downloaded = client.post(
        "/backup/download",
        data={"csrf_token": token, "passphrase": "example-passphrase"},
    )
    assert downloaded.status_code == 200
    assert b"example-router-secret" not in downloaded.data
    payload = decrypt_backup(downloaded.data, "example-passphrase")
    assert payload["routers"][0]["site_name"] == "ExampleSite"

    page = client.get("/routers")
    token = _csrf(page.get_data(as_text=True))
    router_id = json.loads((data / "data.json").read_text(encoding="utf-8"))["routers"][0]["id"]
    client.post(f"/routers/{router_id}/enabled", data={"csrf_token": token, "enabled": "0"})
    page = client.get("/backup")
    token = _csrf(page.get_data(as_text=True))
    restored = client.post(
        "/backup/restore",
        data={
            "csrf_token": token,
            "passphrase": "example-passphrase",
            "backup": (io_bytes(downloaded.data), "easy-radius-backup.erbackup"),
        },
        follow_redirects=True,
    )
    assert restored.status_code == 200
    saved = json.loads((data / "data.json").read_text(encoding="utf-8"))
    assert saved["routers"][0]["enabled"] is True


def io_bytes(blob: bytes):
    from io import BytesIO

    return BytesIO(blob)


def test_totp_is_required_after_it_is_enabled(tmp_path):
    from easy_radius.totp import totp_at

    client, data = _client(tmp_path)
    page = client.get("/security")
    token = _csrf(page.get_data(as_text=True))
    client.post("/security/start", data={"csrf_token": token})
    state_path = data / "data.json"
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    saved["totp_pending_secret"] = RFC_SECRET
    state_path.write_text(json.dumps(saved), encoding="utf-8")
    os.chmod(state_path, 0o600)
    page = client.get("/security")
    token = _csrf(page.get_data(as_text=True))
    code = totp_at(RFC_SECRET, int(__import__("time").time()))
    turned_on = client.post(
        "/security/confirm",
        data={"csrf_token": token, "code": code},
        follow_redirects=True,
    )
    assert "Authenticator codes are on" in turned_on.get_data(as_text=True)
    client.post("/logout", data={"csrf_token": _csrf(turned_on.get_data(as_text=True))})
    page = client.get("/login")
    token = _csrf(page.get_data(as_text=True))
    needs_code = client.post(
        "/login",
        data={"username": "neill", "password": "example-password", "csrf_token": token},
    )
    assert needs_code.status_code == 200
    assert "Authenticator code" in needs_code.get_data(as_text=True)
    token = _csrf(needs_code.get_data(as_text=True))
    code = totp_at(RFC_SECRET, int(__import__("time").time()))
    signed_in = client.post(
        "/login",
        data={
            "username": "neill",
            "password": "example-password",
            "code": code,
            "csrf_token": token,
        },
    )
    assert signed_in.status_code == 302
