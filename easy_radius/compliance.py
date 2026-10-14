"""Pass/fail checks for a few RouterOS settings, and a task that fixes them."""

from __future__ import annotations

from easy_radius.automation import Template, Step, same_value


def _disabled(value: object) -> bool:
    return same_value(value, "true") or same_value(value, "yes")


def _service(rows: list[dict], name: str) -> dict | None:
    for row in rows:
        if str(row.get("name", "")).lower() == name:
            return row
    return None


def evaluate(session, server_address: str = "") -> list[dict]:
    services = session.rows("/ip/service") if hasattr(session, "rows") else [session.get("/ip/service")]
    users = session.rows("/user") if hasattr(session, "rows") else [session.get("/user")]
    ntp = session.get("/system/ntp/client")
    aaa = session.get("/user/aaa")
    checks = []

    def add(check_id: str, title: str, passed: bool, detail: str) -> None:
        checks.append({"id": check_id, "title": title, "passed": passed, "detail": detail})

    for name in ("telnet", "ftp", "www"):
        row = _service(services, name)
        passed = row is not None and _disabled(row.get("disabled"))
        add(name, f"{name} is off", passed, "disabled" if passed else "still enabled")
    admin = next((row for row in users if str(row.get("name", "")).lower() == "admin"), None)
    admin_ok = admin is None or _disabled(admin.get("disabled"))
    add("admin", "Default admin is removed or disabled", admin_ok, "no enabled admin user" if admin_ok else "admin can still log in")
    servers = str(ntp.get("servers") or "").strip()
    ntp_ok = same_value(ntp.get("enabled"), "true") and servers not in {"", "none"}
    add("ntp", "NTP client is set", ntp_ok, "enabled with a server" if ntp_ok else "enable NTP and set a server")
    ssl = _service(services, "api-ssl")
    address = str((ssl or {}).get("address") or "").strip()
    ssl_ok = ssl is not None and not _disabled(ssl.get("disabled")) and address not in {"", "0.0.0.0/0", "::/0"}
    add("api-ssl", "api-ssl is restricted to an address", ssl_ok, address or "no address limit")
    plain = _service(services, "api")
    plain_off = plain is None or _disabled(plain.get("disabled"))
    add("api", "Plaintext API is off", plain_off, "disabled" if plain_off else "port 8728 is enabled")
    radius_ok = same_value(aaa.get("use-radius"), "true")
    add("radius", "RADIUS login is enabled", radius_ok, "use-radius is on" if radius_ok else "use-radius is off")
    return checks


def score(checks: list[dict]) -> tuple[int, int]:
    passed = sum(1 for check in checks if check["passed"])
    return passed, len(checks)


def fix_template(server_address: str) -> Template:
    steps = [
        Step("/ip/service", {"disabled": "yes"}, {"name": "telnet"}),
        Step("/ip/service", {"disabled": "yes"}, {"name": "ftp"}),
        Step("/ip/service", {"disabled": "yes"}, {"name": "www"}),
        Step("/ip/service", {"disabled": "yes"}, {"name": "api"}),
        Step("/user/aaa", {"use-radius": "yes"}, {}),
        Step("/user", {"disabled": "yes"}, {"name": "admin"}),
    ]
    if server_address:
        steps.append(Step("/ip/service", {"address": f"{server_address}/32", "disabled": "no"}, {"name": "api-ssl"}))
    return Template(name="Compliance fix", variables={}, steps=steps)
