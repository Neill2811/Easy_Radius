"""PPPoE failure lines read from routers, kept on this server.

The poll only prints /log and /ppp/active. It does not change a router.
Secrets are not stored. Times are kept in UTC and shown in SAST.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

SAST = ZoneInfo("Africa/Johannesburg")
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAC = re.compile(r"(?i)(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_IFACE = re.compile(r"<pppoe-([^>]+)>", re.IGNORECASE)
_USER = re.compile(r"\buser\s+\"?([A-Za-z0-9_.@+-]+)\"?", re.IGNORECASE)
_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}
_FAILURES = (
    "authentication failed",
    "authentication failure",
    "auth failed",
    "login failed",
    "peer is not responding",
    "terminating",
    "failed",
)


def default_settings() -> dict:
    return {"enabled": True, "interval_minutes": 15, "threshold": 10, "last_run": ""}


def settings_of(state: dict) -> dict:
    found = {**default_settings(), **(state.get("pppoe_poll") or {})}
    try:
        found["interval_minutes"] = max(1, min(1440, int(found.get("interval_minutes") or 15)))
    except (TypeError, ValueError):
        found["interval_minutes"] = 15
    try:
        found["threshold"] = max(1, min(100000, int(found.get("threshold") or 10)))
    except (TypeError, ValueError):
        found["threshold"] = 10
    found["enabled"] = bool(found.get("enabled", True))
    found["last_run"] = str(found.get("last_run") or "")
    return found


def parse_failure(message: str) -> tuple[str, str] | None:
    """Username and MAC from one PPPoE failure line. None when it is not a failure."""
    text = str(message or "").strip()
    low = text.lower()
    if "authenticated" in low and "fail" not in low:
        return None
    if not any(word in low for word in _FAILURES):
        return None
    mac = ""
    username = ""
    mac_match = _MAC.search(text)
    if mac_match:
        mac = _normal_mac(mac_match.group(0))
    user_match = _USER.search(text)
    if user_match:
        username = user_match.group(1)
    iface = _IFACE.search(text)
    if iface:
        token = iface.group(1).strip()
        if _MAC.fullmatch(token):
            mac = mac or _normal_mac(token)
        elif token and not username:
            username = token
    if not username and not mac:
        return None
    return username, mac


def topics_include_ppp(topics: object) -> bool:
    if isinstance(topics, (list, tuple)):
        text = ",".join(str(part) for part in topics)
    else:
        text = str(topics or "")
    parts = {part.strip().lower() for part in text.replace(";", ",").split(",") if part.strip()}
    return bool(parts & {"ppp", "pppoe"})


def parse_log_time(raw: str, now: datetime) -> datetime | None:
    """RouterOS log clock, read as South African Standard Time."""
    text = " ".join(str(raw or "").split())
    if not text:
        return None
    moment = now.astimezone(SAST)
    matched = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", text)
    if matched:
        return _sast(*[int(part) for part in matched.groups()])
    matched = re.fullmatch(r"([A-Za-z]{3})/(\d{1,2})/(\d{4}) (\d{2}):(\d{2}):(\d{2})", text)
    if matched:
        month = _MONTHS.get(matched.group(1).lower())
        if month:
            return _sast(int(matched.group(3)), month, int(matched.group(2)), *[int(part) for part in matched.groups()[3:]])
    matched = re.fullmatch(r"([A-Za-z]{3})/(\d{1,2}) (\d{2}):(\d{2}):(\d{2})", text)
    if matched:
        month = _MONTHS.get(matched.group(1).lower())
        if month:
            year = moment.year
            parsed = _sast(year, month, int(matched.group(2)), *[int(part) for part in matched.groups()[2:]])
            if parsed and parsed > moment + timedelta(days=2):
                parsed = _sast(year - 1, month, int(matched.group(2)), *[int(part) for part in matched.groups()[2:]])
            return parsed
    matched = re.fullmatch(r"(\d{2}):(\d{2}):(\d{2})", text)
    if matched:
        parsed = moment.replace(
            hour=int(matched.group(1)),
            minute=int(matched.group(2)),
            second=int(matched.group(3)),
            microsecond=0,
        )
        if parsed > moment + timedelta(minutes=5):
            parsed -= timedelta(days=1)
        return parsed
    return None


def active_identity(rows: list[dict]) -> tuple[set[str], set[str]]:
    """Usernames and MACs currently in /ppp/active."""
    users: set[str] = set()
    macs: set[str] = set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        iface = _IFACE.search(name)
        token = iface.group(1) if iface else name.strip("<>")
        if token and _MAC.fullmatch(token):
            macs.add(_normal_mac(token))
        elif token:
            users.add(token.lower())
        caller = row.get("caller-id") or row.get("caller-id") or ""
        found = _MAC.search(str(caller))
        if found:
            macs.add(_normal_mac(found.group(0)))
    return users, macs


def poll_routers(state: dict, data_dir: Path, connector, now: datetime | None = None) -> dict:
    """Read each enabled router. A failure on one router does not stop the rest."""
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    settings = settings_of(state)
    from easy_radius.automation import AutomationError, account_password

    routers = [router for router in (state.get("routers") or []) if isinstance(router, dict) and router.get("enabled", True) is not False]
    try:
        username, password = account_password(state)
    except AutomationError as exc:
        detail = _scrub(str(exc), "")
        for router in routers:
            _write_poll(data_dir, router, "failed", detail, moment)
        settings["last_run"] = _iso(moment)
        state["pppoe_poll"] = settings
        return settings
    for router in routers:
        session = None
        try:
            session = _open(connector, router, username, password)
            logs = session.rows("/log") if hasattr(session, "rows") else []
            active = session.rows("/ppp/active") if hasattr(session, "rows") else []
            ingest(data_dir, str(router.get("id") or ""), logs, active, moment, password)
            _write_poll(data_dir, router, "ok", "", moment)
        except Exception as exc:
            _write_poll(data_dir, router, "failed", _scrub(str(exc), password), moment)
        finally:
            close = getattr(session, "close", None)
            if close:
                try:
                    close()
                except Exception:
                    pass
    settings["last_run"] = _iso(moment)
    state["pppoe_poll"] = settings
    return settings


def ingest(data_dir: Path, router_id: str, logs: list[dict], active: list[dict], now: datetime, password: str = "") -> dict:
    store = _load(data_dir, router_id)
    seen = set(store.get("seen") or [])
    events = list(store.get("events") or [])
    for row in logs or []:
        if not isinstance(row, dict) or not topics_include_ppp(row.get("topics")):
            continue
        message = _scrub(str(row.get("message") or ""), password)
        parsed = parse_failure(message)
        if parsed is None:
            continue
        raw_time = str(row.get("time") or "")
        key = raw_time + "\n" + message
        if key in seen:
            continue
        seen.add(key)
        username, mac = parsed
        when = parse_log_time(raw_time, now)
        events.append(
            {
                "key": key,
                "time": raw_time,
                "at": _iso(when) if when else _iso(now),
                "message": message,
                "username": username,
                "mac": mac,
            }
        )
    users, macs = active_identity(active)
    cleared = dict(store.get("cleared") or {})
    for event in events:
        if _is_online(event.get("username") or "", event.get("mac") or "", users, macs):
            identity = _identity(event.get("username") or "", event.get("mac") or "")
            cleared[identity] = _iso(now)
    cutoff = _iso(now - timedelta(days=30))
    events = [event for event in events if str(event.get("at") or "") >= cutoff]
    seen = {event["key"] for event in events if event.get("key")}
    store["events"] = events
    store["seen"] = sorted(seen)
    store["cleared"] = {key: value for key, value in cleared.items() if value >= cutoff}
    _save(data_dir, router_id, store)
    return store


def mark_removed(data_dir: Path, router_id: str, username: str, mac: str, now: datetime | None = None) -> None:
    moment = now or datetime.now(timezone.utc)
    store = _load(data_dir, router_id)
    removed = dict(store.get("removed") or {})
    removed[_identity(username, mac)] = _iso(moment)
    store["removed"] = removed
    _save(data_dir, router_id, store)


def aggregates(data_dir: Path, state: dict, now: datetime | None = None) -> list[dict]:
    """One row per router, username, and MAC, counting failures in the last 24 hours."""
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    day = _iso(moment - timedelta(hours=24))
    names = {str(router.get("id")): router.get("site_name") or router.get("id") for router in (state.get("routers") or []) if isinstance(router, dict)}
    rows = []
    for path in _files(data_dir):
        router_id = path.stem
        store = _read(path)
        grouped: dict[str, dict] = {}
        for event in store.get("events") or []:
            if not isinstance(event, dict):
                continue
            identity = _identity(event.get("username") or "", event.get("mac") or "")
            bucket = grouped.setdefault(
                identity,
                {"username": event.get("username") or "", "mac": event.get("mac") or "", "events": []},
            )
            bucket["events"].append(event)
        removed = store.get("removed") or {}
        cleared = store.get("cleared") or {}
        for identity, bucket in grouped.items():
            cutoff = max(str(removed.get(identity) or ""), str(cleared.get(identity) or ""))
            kept = [event for event in bucket["events"] if str(event.get("at") or "") > cutoff]
            recent = [event for event in kept if str(event.get("at") or "") >= day]
            if not kept:
                continue
            stamps = sorted(str(event.get("at") or "") for event in recent or kept)
            last = stamps[-1] if recent else ""
            first = sorted(str(event.get("at") or "") for event in kept)[0]
            lines = sorted(kept, key=lambda event: str(event.get("at") or ""), reverse=True)[:12]
            rows.append(
                {
                    "router_id": router_id,
                    "site_name": names.get(router_id) or router_id,
                    "username": bucket["username"],
                    "mac": bucket["mac"],
                    "count": len(recent),
                    "first_seen": format_sast(first),
                    "last_seen": format_seen(last or stamps[-1], moment),
                    "last_at": last or stamps[-1],
                    "lines": [{"time": format_sast(event.get("at")), "message": event.get("message") or ""} for event in lines],
                }
            )
    rows.sort(key=lambda row: (-row["count"], row["site_name"], row["username"], row["mac"]))
    return rows


def hot_entries(data_dir: Path, state: dict, now: datetime | None = None) -> list[dict]:
    threshold = settings_of(state)["threshold"]
    return [row for row in aggregates(data_dir, state, now) if row["count"] >= threshold]


def attention_lines(data_dir: Path, state: dict, now: datetime) -> list[dict]:
    moment = datetime.fromtimestamp(now, timezone.utc) if isinstance(now, (int, float)) else now
    lines = []
    for row in hot_entries(data_dir, state, moment):
        who = row["username"] or "unknown user"
        mac = f", MAC {row['mac']}" if row["mac"] else ""
        lines.append(
            {
                "title": row["site_name"],
                "reason": f"{who}{mac}, {row['count']} failed attempts, last seen {row['last_seen']}",
                "endpoint": "pppoe_failures",
            }
        )
    return lines


def poll_status(data_dir: Path, state: dict) -> list[dict]:
    names = {str(router.get("id")): router for router in (state.get("routers") or []) if isinstance(router, dict)}
    found = []
    seen = set()
    for router_id, router in names.items():
        store = _load(data_dir, router_id) if _SAFE_ID.fullmatch(router_id) else {}
        poll = store.get("poll") if isinstance(store.get("poll"), dict) else {}
        found.append(
            {
                "router_id": router_id,
                "site_name": router.get("site_name") or router_id,
                "status": poll.get("status") or "",
                "detail": poll.get("detail") or "",
                "at": format_sast(poll.get("at")),
            }
        )
        seen.add(router_id)
    found.sort(key=lambda row: (row["status"] != "failed", row["site_name"]))
    return found


def due(state: dict, now: datetime) -> bool:
    settings = settings_of(state)
    if not settings["enabled"]:
        return False
    last = settings["last_run"]
    if not last:
        return True
    previous = _parse_iso(last)
    if previous is None:
        return True
    return now - previous >= timedelta(minutes=settings["interval_minutes"])


def format_sast(value) -> str:
    moment = _parse_iso(str(value or ""))
    if moment is None:
        return ""
    return moment.astimezone(SAST).strftime("%Y-%m-%d %H:%M SAST")


def format_seen(value, now: datetime) -> str:
    moment = _parse_iso(str(value or ""))
    if moment is None:
        return ""
    local = moment.astimezone(SAST)
    if local.date() == now.astimezone(SAST).date():
        return local.strftime("%H:%M")
    return local.strftime("%Y-%m-%d %H:%M")


def _identity(username: str, mac: str) -> str:
    return f"{username}\n{mac}"


def _is_online(username: str, mac: str, users: set[str], macs: set[str]) -> bool:
    if username and username.lower() in users:
        return True
    if mac and mac in macs:
        return True
    return False


def _normal_mac(value: str) -> str:
    parts = re.split(r"[:-]", value.strip())
    return ":".join(part.upper() for part in parts)


def _sast(year: int, month: int, day: int, hour: int, minute: int, second: int) -> datetime | None:
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=SAST)
    except ValueError:
        return None


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def _scrub(text: str, password: str) -> str:
    if password and password in text:
        return text.replace(password, "<password>")
    return text


def _open(connector, router, username, password):
    allow = bool(router.get("api_plaintext"))
    try:
        return connector(router["ip"], username, password, allow_plaintext=allow)
    except TypeError:
        return connector(router["ip"], username, password)


def _folder(data_dir: Path) -> Path:
    path = Path(data_dir) / "pppoe-failures"
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _path(data_dir: Path, router_id: str) -> Path:
    if not _SAFE_ID.fullmatch(router_id or ""):
        raise ValueError("Unknown router")
    return _folder(data_dir) / f"{router_id}.json"


def _files(data_dir: Path) -> list[Path]:
    folder = Path(data_dir) / "pppoe-failures"
    if not folder.is_dir():
        return []
    return sorted(path for path in folder.glob("*.json") if _SAFE_ID.fullmatch(path.stem))


def _empty() -> dict:
    return {"events": [], "seen": [], "cleared": {}, "removed": {}, "poll": {}}


def _load(data_dir: Path, router_id: str) -> dict:
    if not _SAFE_ID.fullmatch(router_id or ""):
        return _empty()
    path = Path(data_dir) / "pppoe-failures" / f"{router_id}.json"
    if not path.is_file():
        return _empty()
    return _read(path)


def _read(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty()
    if not isinstance(payload, dict):
        return _empty()
    base = _empty()
    base.update(payload)
    return base


def _save(data_dir: Path, router_id: str, store: dict) -> None:
    path = _path(data_dir, router_id)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(store, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)


def _write_poll(data_dir: Path, router: dict, status: str, detail: str, now: datetime) -> None:
    router_id = str(router.get("id") or "")
    if not _SAFE_ID.fullmatch(router_id):
        return
    store = _load(data_dir, router_id)
    store["poll"] = {"at": _iso(now), "status": status, "detail": detail[:300]}
    _save(data_dir, router_id, store)
