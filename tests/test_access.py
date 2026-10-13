from easy_radius.access import access_label, render_access_policy, request_allowed
from easy_radius.apply import apply_configuration, run_radtest
from easy_radius.hostcmd import CommandResult

ROUTERS = [
    {
        "id": "r1",
        "site_name": "ExampleSite",
        "ip": "192.0.2.10",
        "secret": "example-router-secret",
        "enabled": True,
        "tags": ["North"],
    },
    {
        "id": "r2",
        "site_name": "Example North",
        "ip": "192.0.2.11",
        "secret": "example-north-secret",
        "enabled": True,
        "tags": ["North"],
    },
    {
        "id": "r3",
        "site_name": "Example South",
        "ip": "198.51.100.20",
        "secret": "example-south-secret",
        "enabled": False,
        "tags": ["South"],
    },
]


def _user(**extra):
    user = {
        "username": "alice",
        "password": "example-password",
        "group": "write",
        "enabled": True,
        "access": "all",
        "router_ids": [],
        "access_tags": [],
    }
    user.update(extra)
    return user


def test_all_routers_allows_any_source_and_omits_the_user_from_the_policy():
    user = _user()
    assert request_allowed(user, ROUTERS, "203.0.113.9", "other", "")
    policy = render_access_policy([user], ROUTERS)
    assert "alice" not in policy
    assert "easy_radius_access" in policy
    assert "noop" in policy


def test_restricted_user_allowed_and_denied_including_radtest_nas_address():
    user = _user(access="routers", router_ids=["r1"])
    assert request_allowed(user, ROUTERS, "192.0.2.10", "ExampleSite", "")
    assert request_allowed(user, ROUTERS, "192.0.2.10", "localhost", "203.0.113.9")
    assert not request_allowed(user, ROUTERS, "192.0.2.11", "Example North", "192.0.2.10")
    assert request_allowed(user, ROUTERS, "127.0.0.1", "localhost", "192.0.2.10")
    assert request_allowed(user, ROUTERS, "::1", "localhost", "192.0.2.10")
    assert not request_allowed(user, ROUTERS, "127.0.0.1", "localhost", "192.0.2.11")
    assert not request_allowed(user, ROUTERS, "127.0.0.1", "localhost", "")
    policy = render_access_policy([user], ROUTERS)
    assert '&User-Name == "alice"' in policy
    assert "&Packet-Src-IP-Address == 192.0.2.10" in policy
    assert '&Client-Shortname == "ExampleSite"' in policy
    assert "&NAS-IP-Address == 192.0.2.10" in policy
    assert "192.0.2.11" not in policy
    assert "198.51.100.20" not in policy
    assert access_label(user, ROUTERS) == "ExampleSite"


def test_site_group_allows_every_router_with_that_tag():
    user = _user(access="routers", access_tags=["North"])
    assert request_allowed(user, ROUTERS, "192.0.2.11", "Example North", "")
    assert not request_allowed(user, ROUTERS, "198.51.100.20", "Example South", "")
    policy = render_access_policy([user], ROUTERS)
    assert "192.0.2.10" in policy
    assert "192.0.2.11" in policy
    assert '&Client-Shortname == "Example North"' in policy
    assert access_label(user, ROUTERS) == "North"


def test_empty_choice_rejects_every_router():
    user = _user(access="routers")
    assert not request_allowed(user, ROUTERS, "192.0.2.10", "ExampleSite", "")
    assert not request_allowed(user, ROUTERS, "127.0.0.1", "localhost", "192.0.2.10")
    policy = render_access_policy([user], ROUTERS)
    assert "reject" in policy
    assert "192.0.2.10" not in policy
    assert access_label(user, ROUTERS) == "No routers"


def test_apply_writes_policy_and_restores_it_when_the_check_fails(tmp_path):
    clients = tmp_path / "clients.conf"
    users = tmp_path / "authorize"
    policy = tmp_path / "easy_radius"
    clients.write_text("ORIGINAL CLIENTS\n", encoding="utf-8")
    users.write_text("ORIGINAL USERS\n", encoding="utf-8")
    policy.write_text("ORIGINAL POLICY\n", encoding="utf-8")

    class Runner:
        def __init__(self):
            self.calls = []

        def __call__(self, args, timeout=120):
            self.calls.append(list(args))
            if args[:2] == ["freeradius", "-XC"]:
                return CommandResult(list(args), 1, "", "parse error\n")
            if args and args[0] == "sh":
                return CommandResult(list(args), 0, "", "")
            return CommandResult(list(args), 1, "", "unexpected\n")

    state = {
        "localhost_secret": "example-localhost-secret",
        "routers": ROUTERS,
        "users": [_user(access="routers", router_ids=["r1"])],
    }
    failed = Runner()
    result = apply_configuration(state, failed, clients, users, tmp_path / "backups", policy)
    assert result.rolled_back
    assert policy.read_text(encoding="utf-8") == "ORIGINAL POLICY\n"
    assert not any(call[:3] == ["systemctl", "restart", "freeradius"] for call in failed.calls)
    ok = apply_configuration(
        state,
        type("R", (), {"__call__": lambda self, args, timeout=120: CommandResult(list(args), 0, "active\n" if args[:3] == ["systemctl", "is-active", "freeradius"] else "Configuration appears to be OK.\n", "")})(),
        clients,
        users,
        tmp_path / "backups",
        policy,
    )
    assert ok.ok
    written = policy.read_text(encoding="utf-8")
    assert '&User-Name == "alice"' in written
    assert "192.0.2.10" in written


def test_radtest_can_name_the_router():
    seen = {}

    def runner(args, timeout=120):
        seen["args"] = args
        return CommandResult(list(args), 0, "", "")

    run_radtest("alice", "example-password", "example-localhost-secret", runner, nas_ip="192.0.2.10")
    assert seen["args"] == [
        "radtest",
        "alice",
        "example-password",
        "127.0.0.1",
        "0",
        "example-localhost-secret",
        "0",
        "192.0.2.10",
    ]
