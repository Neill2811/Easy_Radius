"""Per-user router access, and the FreeRADIUS policy that enforces it.

A user is allowed on a router when any of these match an allowed router:

- the packet came from that router's IP
- FreeRADIUS's Client-Shortname is that router's site name
- the packet came from localhost and NAS-IP-Address is that router's IP

The localhost case is how radtest on this server checks a chosen router.
A packet from any other address cannot pass by setting NAS-IP-Address alone.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$")
_LOOPBACK = (ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1"))


def parse_tags(raw: str) -> tuple[list[str], str | None]:
    tags: list[str] = []
    for part in (raw or "").split(","):
        tag = part.strip()
        if not tag:
            continue
        if not _TAG.fullmatch(tag):
            return [], "Tags use letters, numbers, spaces, and . _ -"
        if tag not in tags:
            tags.append(tag)
    return tags, None


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def granted_routers(user: dict, routers: list[dict]) -> list[dict] | None:
    """Routers this user may use. None means every router."""
    if user.get("enabled", True) is False:
        return []
    if user.get("access", "all") != "routers":
        return None
    wanted = set(user.get("router_ids") or [])
    tags = {tag.casefold() for tag in user.get("access_tags") or []}
    granted: list[dict] = []
    seen: set[str] = set()
    for router in routers:
        if router.get("enabled", True) is False:
            continue
        router_tags = {tag.casefold() for tag in router.get("tags") or []}
        if router.get("id") not in wanted and not (tags & router_tags):
            continue
        if router["id"] in seen:
            continue
        seen.add(router["id"])
        granted.append(router)
    return granted


def request_allowed(
    user: dict,
    routers: list[dict],
    packet_src: str,
    client_shortname: str,
    nas_ip: str = "",
) -> bool:
    granted = granted_routers(user, routers)
    if granted is None:
        return True
    src = _ip(packet_src)
    nas = _ip(nas_ip)
    loopback = src in _LOOPBACK if src is not None else False
    for router in granted:
        router_ip = _ip(router.get("ip", ""))
        if router_ip is None:
            continue
        if src == router_ip:
            return True
        if client_shortname == router.get("site_name"):
            return True
        if loopback and nas == router_ip:
            return True
    return False


def users_with_grants(users: list[dict], grants: list[dict], now: datetime | None = None) -> list[dict]:
    """Add temporary router access that has not expired yet.

    A user who already has all routers is left unchanged. Grants do not
    remove access.
    """
    moment = now or datetime.now(timezone.utc)
    now_text = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    extra: dict[str, dict[str, list]] = {}
    for grant in grants or []:
        if str(grant.get("expires_at") or "") <= now_text:
            continue
        bucket = extra.setdefault(str(grant.get("user_id")), {"ids": [], "tags": []})
        for router_id in grant.get("router_ids") or []:
            if router_id not in bucket["ids"]:
                bucket["ids"].append(router_id)
        for tag in grant.get("tags") or []:
            if tag not in bucket["tags"]:
                bucket["tags"].append(tag)
    if not extra:
        return list(users)
    expanded = []
    for user in users:
        bonus = extra.get(str(user.get("id")))
        if not bonus or user.get("access", "all") != "routers":
            expanded.append(user)
            continue
        copy = dict(user)
        router_ids = list(user.get("router_ids") or [])
        tags = list(user.get("access_tags") or [])
        for router_id in bonus["ids"]:
            if router_id not in router_ids:
                router_ids.append(router_id)
        for tag in bonus["tags"]:
            if tag not in tags:
                tags.append(tag)
        copy["router_ids"] = router_ids
        copy["access_tags"] = tags
        expanded.append(copy)
    return expanded


def drop_expired_grants(state: dict, now: datetime | None = None) -> list[dict]:
    moment = now or datetime.now(timezone.utc)
    now_text = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    kept = []
    expired = []
    for grant in state.get("grants") or []:
        if str(grant.get("expires_at") or "") <= now_text:
            expired.append(grant)
        else:
            kept.append(grant)
    state["grants"] = kept
    return expired


def access_label(user: dict, routers: list[dict]) -> str:
    if user.get("access", "all") != "routers":
        return "All routers"
    by_id = {router["id"]: router for router in routers}
    names = []
    for router_id in user.get("router_ids") or []:
        router = by_id.get(router_id)
        names.append(router["site_name"] if router else router_id)
    names.extend(user.get("access_tags") or [])
    return ", ".join(names) if names else "No routers"


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_access_policy(users: list[dict], routers: list[dict], when: datetime | None = None) -> str:
    stamp = (when or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# Generated by Easy Radius. This file is replaced when you click Apply.",
        "# A restricted user is rejected unless the request is from an allowed router.",
        "# radtest on this server can set NAS-IP-Address to that router's IP.",
        f"# Last written: {stamp}",
        "",
        "easy_radius_access {",
    ]
    for user in users:
        if user.get("enabled", True) is False:
            continue
        granted = granted_routers(user, routers)
        if granted is None:
            continue
        username = _quote(user["username"])
        lines.append(f"\tif (&User-Name == {username}) {{")
        if not granted:
            lines.append("\t\tupdate reply {")
            lines.append('\t\t\tReply-Message := "Not allowed on this router"')
            lines.append("\t\t}")
            lines.append("\t\treject")
        else:
            checks = []
            for router in granted:
                ip = router["ip"]
                short = _quote(router["site_name"])
                checks.append(f"(&Packet-Src-IP-Address == {ip})")
                checks.append(f"(&Client-Shortname == {short})")
                checks.append(
                    f'((&Packet-Src-IP-Address == 127.0.0.1 || "%{{Packet-Src-IP-Address}}" == "::1") && (&NAS-IP-Address == {ip}))'
                )
            joined = " || ".join(checks)
            lines.append(f"\t\tif (!({joined})) {{")
            lines.append("\t\t\tupdate reply {")
            lines.append('\t\t\t\tReply-Message := "Not allowed on this router"')
            lines.append("\t\t\t}")
            lines.append("\t\t\treject")
            lines.append("\t\t}")
        lines.append("\t}")
    lines.append("\tnoop")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)
