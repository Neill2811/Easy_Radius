"""Parse the Easy Radius FreeRADIUS linelog files."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

AUTH_LINE = re.compile(
    r"^EASYRADIUS auth time=(\d+) result=(Access-Accept|Access-Reject) user=(\S*) nas=(\S*)\s*$"
)
ACCT_LINE = re.compile(
    r"^EASYRADIUS acct time=(\d+) status=(\S*) user=(\S*) nas=(\S*) session=(\S*)\s*$"
)
_ONLINE_UPDATES = {"Start", "Interim-Update", "Alive"}
_STOP = {"Stop"}


def tail_text(path: Path, max_bytes: int = 512_000) -> str:
    path = Path(path)
    if not path.is_file():
        return ""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    try:
        handle = path.open("rb")
    except OSError:
        return ""
    with handle:
        if size > max_bytes:
            handle.seek(size - max_bytes)
            handle.readline()
        data = handle.read()
    return data.decode("utf-8", "replace")


def _clean(value: str) -> str:
    if value in {"", "-"}:
        return ""
    return value


def parse_auth_log(text: str) -> list[dict]:
    events = []
    for line in text.splitlines():
        match = AUTH_LINE.match(line.strip())
        if not match:
            continue
        events.append(
            {
                "time": int(match.group(1)),
                "result": match.group(2),
                "user": _clean(match.group(3)),
                "nas": _clean(match.group(4)),
            }
        )
    events.sort(key=lambda item: item["time"], reverse=True)
    return events


def parse_acct_log(text: str) -> list[dict]:
    events = []
    for line in text.splitlines():
        match = ACCT_LINE.match(line.strip())
        if not match:
            continue
        events.append(
            {
                "time": int(match.group(1)),
                "status": match.group(2),
                "user": _clean(match.group(3)),
                "nas": _clean(match.group(4)),
                "session": _clean(match.group(5)),
            }
        )
    events.sort(key=lambda item: item["time"])
    return events


def _same_ip(left: str, right: str) -> bool:
    if not left or not right:
        return False
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return left == right


def filter_auth(events: list[dict], user: str = "", nas: str = "", result: str = "") -> list[dict]:
    user_q = user.strip().lower()
    found = []
    for event in events:
        if user_q and user_q not in event["user"].lower():
            continue
        if nas and not _same_ip(event["nas"], nas):
            continue
        if result and event["result"] != result:
            continue
        found.append(event)
    return found


def session_view(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (online sessions, history newest first)."""
    ordered = sorted(events, key=lambda item: item["time"])
    open_sessions: dict[tuple, dict] = {}
    for event in ordered:
        status = event["status"]
        if status in {"Accounting-Off", "Accounting-On"}:
            for key, row in list(open_sessions.items()):
                if _same_ip(key[1], event["nas"]) and row["online"]:
                    row["online"] = False
                    row["stop"] = event["time"]
            continue
        key = (event["user"], event["nas"], event["session"])
        row = open_sessions.get(key)
        if status in _STOP:
            if row is None:
                open_sessions[key] = {
                    "user": event["user"],
                    "nas": event["nas"],
                    "session": event["session"],
                    "start": None,
                    "stop": event["time"],
                    "last": event["time"],
                    "online": False,
                }
            else:
                row["online"] = False
                row["stop"] = event["time"]
                row["last"] = event["time"]
            continue
        if status == "Start":
            open_sessions[key] = {
                "user": event["user"],
                "nas": event["nas"],
                "session": event["session"],
                "start": event["time"],
                "stop": None,
                "last": event["time"],
                "online": True,
            }
            continue
        if status not in _ONLINE_UPDATES:
            continue
        if row is None:
            open_sessions[key] = {
                "user": event["user"],
                "nas": event["nas"],
                "session": event["session"],
                "start": event["time"],
                "stop": None,
                "last": event["time"],
                "online": True,
            }
        elif row["online"]:
            row["last"] = event["time"]
    online = [row for row in open_sessions.values() if row["online"]]
    online.sort(key=lambda item: item["last"], reverse=True)
    history = sorted(ordered, key=lambda item: item["time"], reverse=True)
    return online, history


def router_health(routers: list[dict], packet_times: list[tuple[str, int]], now: int, window: int) -> list[dict]:
    rows = []
    for router in routers:
        last = None
        for nas, when in packet_times:
            if _same_ip(nas, router.get("ip", "")) and (last is None or when > last):
                last = when
        age = None if last is None else max(0, now - last)
        rows.append(
            {
                "id": router.get("id"),
                "last_seen": last,
                "age": age,
                "up": age is not None and age <= window,
            }
        )
    return rows


def packet_times(auth_events: list[dict], acct_events: list[dict]) -> list[tuple[str, int]]:
    times = [(event["nas"], event["time"]) for event in auth_events if event["nas"]]
    times.extend((event["nas"], event["time"]) for event in acct_events if event["nas"])
    return times


def format_time(when: int | None) -> str:
    if not when:
        return ""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(when, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_age(age: int | None) -> str:
    if age is None:
        return "no packets yet"
    if age < 60:
        return f"{age}s ago"
    if age < 3600:
        return f"{age // 60} min ago"
    if age < 86400:
        return f"{age // 3600} h ago"
    return f"{age // 86400} d ago"
