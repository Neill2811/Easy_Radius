"""Pass/fail checks for a few RouterOS settings, and a task that fixes them."""

from __future__ import annotations

from easy_radius.automation import Template, Step, same_value

_OPEN = {"", "0.0.0.0/0", "::/0"}
_OFF = ("telnet", "www", "www-ssl")


def _disabled(value: object) -> bool:
    return same_value(value, "true") or same_value(value, "yes")


def _service(rows: list[dict], name: str) -> dict | None:
    for row in rows:
        if str(row.get("name", "")).lower() == name:
            return row
    return None


def _port(row: dict | None) -> str:
    if not row:
        return "unknown"
    port = str(row.get("port") or "").strip()
    return port or "unknown"


def _address_list(row: dict | None) -> list[str]:
    if not row:
        return []
    raw = row.get("addresses")
    if raw is None or str(raw).strip() == "":
        raw = row.get("address") or ""
    return [part.strip() for part in str(raw).split(",") if part.strip()]


def _is_open(addresses: list[str]) -> bool:
    return (not addresses) or any(part in _OPEN for part in addresses)


def _enabled_detail(row: dict, addresses: list[str]) -> str:
    port = _port(row)
    if _is_open(addresses):
        return f"enabled on port {port}, open to any address"
    return f"enabled on port {port}, restricted to {','.join(addresses)}"


def _state_detail(row: dict | None) -> str:
    if row is None:
        return "not present"
    if _disabled(row.get("disabled")):
        return f"disabled on port {_port(row)}"
    return _enabled_detail(row, _address_list(row))


def _must_be_off(row: dict | None) -> tuple[bool, str]:
    if row is not None and _disabled(row.get("disabled")):
        return True, _state_detail(row)
    return False, _state_detail(row)


def _must_be_restricted(row: dict | None) -> tuple[bool, str]:
    """The service must be enabled and limited to specific addresses."""
    if row is None or _disabled(row.get("disabled")):
        return False, _state_detail(row)
    addresses = _address_list(row)
    return (not _is_open(addresses)), _enabled_detail(row, addresses)


def _off_or_restricted(row: dict | None) -> tuple[bool, str]:
    """Pass when the service is missing, disabled, or limited to specific addresses."""
    if row is None or _disabled(row.get("disabled")):
        return True, _state_detail(row)
    addresses = _address_list(row)
    return (not _is_open(addresses)), _enabled_detail(row, addresses)


def evaluate(session, server_address: str = "") -> list[dict]:
    services = session.rows("/ip/service") if hasattr(session, "rows") else [session.get("/ip/service")]
    users = session.rows("/user") if hasattr(session, "rows") else [session.get("/user")]
    ntp = session.get("/system/ntp/client")
    aaa = session.get("/user/aaa")
    checks = []

    def add(check_id: str, title: str, passed: bool, detail: str) -> None:
        checks.append({"id": check_id, "title": title, "passed": passed, "detail": detail})

    for name in _OFF:
        row = _service(services, name)
        passed, detail = _must_be_off(row)
        add(name, f"{name} is off", passed, detail)
    ftp_passed, ftp_detail = _ftp(_service(services, "ftp"))
    add("ftp", "FTP is on and restricted", ftp_passed, ftp_detail)
    ssh = _service(services, "ssh")
    add("ssh", "SSH", True, _state_detail(ssh))
    winbox_passed, winbox_detail = _winbox(_service(services, "winbox"))
    add("winbox", "Winbox is off or restricted", winbox_passed, winbox_detail)
    plain_passed, plain_detail = _plaintext_api(_service(services, "api"))
    add("api", "Plaintext API is off or restricted", plain_passed, plain_detail)
    ssl_passed, ssl_detail = _must_be_restricted(_service(services, "api-ssl"))
    add("api-ssl", "api-ssl is restricted to an address", ssl_passed, ssl_detail)
    admin = next((row for row in users if str(row.get("name", "")).lower() == "admin"), None)
    admin_ok = admin is None or _disabled(admin.get("disabled"))
    add("admin", "Default admin is removed or disabled", admin_ok, "no enabled admin user" if admin_ok else "admin can still log in")
    servers = str(ntp.get("servers") or "").strip()
    ntp_ok = same_value(ntp.get("enabled"), "true") and servers not in {"", "none"}
    add("ntp", "NTP client is set", ntp_ok, "enabled with a server" if ntp_ok else "enable NTP and set a server")
    snmp_passed, snmp_detail = _snmp(session)
    add("snmp", "SNMP", snmp_passed, snmp_detail)
    radius_ok = same_value(aaa.get("use-radius"), "true")
    add("radius", "RADIUS login is enabled", radius_ok, "use-radius is on" if radius_ok else "use-radius is off")
    return checks


def service_summary(session) -> list[dict]:
    """Every /ip service row: name, port, enabled or disabled, allowed addresses."""
    services = session.rows("/ip/service") if hasattr(session, "rows") else [session.get("/ip/service")]
    summary = []
    for row in services:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        addresses = _address_list(row)
        summary.append(
            {
                "name": name,
                "port": _port(row),
                "state": "disabled" if _disabled(row.get("disabled")) else "enabled",
                "addresses": ",".join(addresses),
            }
        )
    return summary


def _ftp(row: dict | None) -> tuple[bool, str]:
    """FTP must stay enabled and limited to specific addresses."""
    return _must_be_restricted(row)


def _winbox(row: dict | None) -> tuple[bool, str]:
    """Winbox may stay on only when the address list is a real set of hosts.

    "On with no ports" is read as enabled with no allowed addresses, not as a
    missing port number. An empty list, 0.0.0.0/0, and ::/0 all fail.
    """
    return _off_or_restricted(row)


def _plaintext_api(row: dict | None) -> tuple[bool, str]:
    """Port 8728 may stay on when it is limited to specific addresses."""
    return _off_or_restricted(row)


def _snmp(session) -> tuple[bool, str]:
    """Describe SNMP without community secrets. Fail on public or open write."""
    try:
        settings = session.get("/snmp") if hasattr(session, "get") else {}
    except Exception:
        settings = {}
    if not isinstance(settings, dict):
        settings = {}
    try:
        communities = session.rows("/snmp/community") if hasattr(session, "rows") else []
    except Exception:
        communities = []
    enabled = same_value(settings.get("enabled"), "true") or same_value(settings.get("enabled"), "yes")
    failures: list[str] = []
    described: list[str] = []
    for row in communities or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip() or "(unnamed)"
        community_on = not _disabled(row.get("disabled"))
        addresses = _address_list(row)
        write = same_value(row.get("write-access"), "true") or same_value(row.get("write-access"), "yes")
        read = same_value(row.get("read-access"), "true") or same_value(row.get("read-access"), "yes")
        if write:
            access = "read-write"
        elif read:
            access = "read"
        else:
            access = "no access"
        security = str(row.get("security") or "").strip() or "none"
        where = "open" if _is_open(addresses) else ",".join(addresses)
        state = "enabled" if community_on else "disabled"
        described.append(f"{name} ({state}, {where}, {access}, security {security})")
        if community_on and name.lower() == "public":
            failures.append("public community is enabled")
        if community_on and write and _is_open(addresses):
            failures.append(f"{name} has write access with no address restriction")
    listed = "; ".join(described) if described else "no communities"
    detail = f"SNMP {'enabled' if enabled else 'disabled'}; {listed}"
    if failures:
        detail = detail + "; " + "; ".join(failures)
    return (not failures), detail


def score(checks: list[dict]) -> tuple[int, int]:
    passed = sum(1 for check in checks if check["passed"])
    return passed, len(checks)


def fix_template(server_address: str) -> Template:
    steps = [
        Step("/ip/service", {"disabled": "yes"}, {"name": "telnet"}),
        Step("/ip/service", {"disabled": "yes"}, {"name": "www"}),
        Step("/ip/service", {"disabled": "yes"}, {"name": "www-ssl"}),
        Step("/user/aaa", {"use-radius": "yes"}, {}),
        Step("/user", {"disabled": "yes"}, {"name": "admin"}),
    ]
    if server_address:
        steps.append(Step("/ip/service", {"address": f"{server_address}/32", "disabled": "no"}, {"name": "api-ssl"}))
    return Template(name="Compliance fix", variables={}, steps=steps)
