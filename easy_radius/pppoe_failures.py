"""PPPoE failure counts read from routers, kept on this server.

The poll only prints /log and /ppp/active. It does not change a router.
Secrets are not stored. Each router has one small file: totals per
username and MAC, hourly buckets for the recent window, and a few raw
lines. Times are kept in UTC and shown in SAST.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import tempfile
import threading
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
_VERSION = 2
_HOUR_KEEP = 48
_LINE_KEEP = 10
_PRUNE_DAYS = 30
_CURSOR_CAP = 2048
_VALUE_CAP = 4_000_000
_LOCK = threading.RLock()
_CACHE: dict[str, tuple[int, int, dict]] = {}
_POLL_MEM: dict[str, dict] = {}
_ROW_CACHE: dict[str, object] = {"sig": None, "rows": None}


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
        caller = row.get("caller-id") or ""
        found = _MAC.search(str(caller))
        if found:
            macs.add(_normal_mac(found.group(0)))
    return users, macs


def poll_routers(state: dict, data_dir: Path, connector, now: datetime | None = None) -> dict:
    """Read each enabled router. A failure on one router does not stop the rest."""
    moment = _as_utc(now)
    settings = settings_of(state)
    from easy_radius.automation import AutomationError, account_password

    routers = [
        router
        for router in (state.get("routers") or [])
        if isinstance(router, dict) and router.get("enabled", True) is not False
    ]
    try:
        _username, password = account_password(state)
    except AutomationError as exc:
        detail = _scrub(str(exc), "")
        for router in routers:
            _record_poll(data_dir, router, "failed", detail, moment)
        settings["last_run"] = _iso(moment)
        state["pppoe_poll"] = settings
        return settings
    for router in routers:
        session = None
        try:
            session = _open(connector, router, _username, password)
            logs = session.rows("/log") if hasattr(session, "rows") else []
            active = session.rows("/ppp/active") if hasattr(session, "rows") else []
            ingest(
                data_dir,
                str(router.get("id") or ""),
                logs,
                active,
                moment,
                password,
                poll=("ok", ""),
            )
        except Exception as exc:
            _record_poll(data_dir, router, "failed", _scrub(str(exc), password), moment)
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


def ingest(
    data_dir: Path,
    router_id: str,
    logs: list[dict],
    active: list[dict],
    now: datetime,
    password: str = "",
    *,
    poll: tuple[str, str] | None = None,
) -> dict:
    """Fold one router's log into its aggregate file. Skip the write when nothing changed."""
    moment = _as_utc(now)
    if not _SAFE_ID.fullmatch(router_id or ""):
        return _empty()
    with _LOCK:
        current = _load(data_dir, router_id)
        store = copy.deepcopy(current)
        cursor_at = _parse_iso(store["cursor"].get("at") or "")
        cursor_ids = set(store["cursor"].get("ids") or [])
        rows = _take_lines(logs, moment, password, cursor_at, cursor_ids)
        _apply_rows(store, rows, moment)
        users, macs = active_identity(active)
        _clear_online(store, users, macs, moment)
        if poll is not None:
            _stage_poll(data_dir, router_id, store, poll[0], poll[1], moment)
        _prune_store(store, moment)
        if store != current:
            _save(data_dir, router_id, store)
        return store


def mark_removed(data_dir: Path, router_id: str, username: str, mac: str, now: datetime | None = None) -> None:
    moment = _as_utc(now)
    if not _SAFE_ID.fullmatch(router_id or ""):
        raise ValueError("Unknown router")
    with _LOCK:
        current = _load(data_dir, router_id)
        store = copy.deepcopy(current)
        identity = _identity(username, mac)
        entry = store["entries"].get(identity)
        if entry is None:
            entry = _blank_entry(username, mac)
            store["entries"][identity] = entry
        entry["removed"] = _iso(moment)
        _drop_hidden(entry, _cutoff(entry))
        _prune_store(store, moment)
        if store != current:
            _save(data_dir, router_id, store)


def aggregates(data_dir: Path, state: dict, now: datetime | None = None) -> list[dict]:
    """One row per router, username, and MAC, counting failures in the last 24 hours."""
    moment = _as_utc(now)
    with _LOCK:
        loaded = []
        sig_parts = []
        for path in _files(data_dir):
            loaded.append((path.stem, _read(path)))
            try:
                st = path.stat()
                sig_parts.append((str(path), st.st_mtime_ns, st.st_size))
            except OSError:
                sig_parts.append((str(path), 0, 0))
        names = {}
        for router in state.get("routers") or []:
            if isinstance(router, dict):
                names[str(router.get("id"))] = router.get("site_name") or router.get("id")
        local = moment.astimezone(SAST)
        sig = (
            tuple(sig_parts),
            tuple(sorted((key, str(value)) for key, value in names.items())),
            local.strftime("%Y-%m-%d"),
            _hour_key(moment),
        )
        if _ROW_CACHE.get("sig") == sig:
            return _ROW_CACHE["rows"]
        window = _window_hours(moment)
        horizon = _iso(moment - timedelta(days=_PRUNE_DAYS))
        rows = []
        for router_id, store in loaded:
            for entry in (store.get("entries") or {}).values():
                row = _row(router_id, names, entry, moment, window, horizon)
                if row:
                    rows.append(row)
        rows.sort(key=lambda row: (-row["count"], row["site_name"], row["username"], row["mac"]))
        _ROW_CACHE["sig"] = sig
        _ROW_CACHE["rows"] = rows
        return rows


def hot_entries(data_dir: Path, state: dict, now: datetime | None = None) -> list[dict]:
    threshold = settings_of(state)["threshold"]
    return [row for row in aggregates(data_dir, state, now) if row["count"] >= threshold]


def attention_lines(data_dir: Path, state: dict, now) -> list[dict]:
    lines = []
    for row in hot_entries(data_dir, state, now):
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
    with _LOCK:
        for router_id, router in names.items():
            poll = _poll_view(data_dir, router_id)
            found.append(
                {
                    "router_id": router_id,
                    "site_name": router.get("site_name") or router_id,
                    "status": poll.get("status") or "",
                    "detail": poll.get("detail") or "",
                    "at": format_sast(poll.get("at")),
                }
            )
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


def migrate_stores(data_dir: Path, now: datetime | None = None) -> None:
    """Convert a previous event log in place. A missing directory is an empty start."""
    folder = Path(data_dir) / "pppoe-failures"
    if not folder.is_dir():
        return
    moment = _as_utc(now)
    for path in sorted(folder.glob("*.json")):
        if not _SAFE_ID.fullmatch(path.stem):
            continue
        with _LOCK:
            if _needs_migration(path):
                _migrate_file(path, moment)


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


def _as_utc(now) -> datetime:
    if isinstance(now, (int, float)):
        return datetime.fromtimestamp(now, timezone.utc)
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now


def _record_poll(data_dir: Path, router: dict, status: str, detail: str, now: datetime) -> None:
    ingest(data_dir, str(router.get("id") or ""), [], [], now, poll=(status, detail))


def _stage_poll(data_dir: Path, router_id: str, store: dict, status: str, detail: str, now: datetime) -> None:
    record = {"at": _iso(now), "status": status, "detail": str(detail or "")[:300]}
    _POLL_MEM[_mem_key(data_dir, router_id)] = record
    previous = store.get("poll") or {}
    if previous.get("status") != record["status"] or previous.get("detail") != record["detail"] or not previous.get("at"):
        store["poll"] = record


def _poll_view(data_dir: Path, router_id: str) -> dict:
    mem = _POLL_MEM.get(_mem_key(data_dir, router_id))
    if mem:
        return mem
    if not _SAFE_ID.fullmatch(router_id or ""):
        return {}
    return _load(data_dir, router_id).get("poll") or {}


def _mem_key(data_dir: Path, router_id: str) -> str:
    try:
        root = str(Path(data_dir).resolve())
    except OSError:
        root = str(data_dir)
    return root + "\0" + router_id


def _take_lines(logs, now: datetime, password: str, cursor_at: datetime | None, cursor_ids: set[str]) -> list[tuple]:
    rows = []
    seen: set[str] = set()
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for row in logs or []:
        if not isinstance(row, dict) or not topics_include_ppp(row.get("topics")):
            continue
        message = _scrub(str(row.get("message") or ""), password)
        if len(message) > 2000:
            message = message[:2000]
        parsed = parse_failure(message)
        if parsed is None:
            continue
        raw_time = str(row.get("time") or "")
        digest = _digest(raw_time + "\n" + message)
        if digest in seen:
            continue
        seen.add(digest)
        when = parse_log_time(raw_time, now)
        if when is None:
            when = epoch if cursor_at is not None or digest in cursor_ids else now
        username, mac = parsed
        rows.append((when, digest, username, mac, message[:500]))
    return rows


def _apply_rows(store: dict, rows: list[tuple], now: datetime) -> None:
    cursor_at = _parse_iso(store["cursor"].get("at") or "")
    ids = set(store["cursor"].get("ids") or [])
    horizon = now - timedelta(days=_PRUNE_DAYS)
    for when, digest, username, mac, message in rows:
        if digest in ids or (cursor_at is not None and when < cursor_at) or when < horizon:
            continue
        _add_failure(store, username, mac, when, message)
    _set_cursor(store, rows)


def _set_cursor(store: dict, rows: list[tuple]) -> None:
    if not rows:
        return
    built_at_dt = max(item[0] for item in rows)
    ranked = sorted(rows, key=lambda item: (item[0], item[1]), reverse=True)
    ids: list[str] = []
    seen: set[str] = set()
    for when, digest, *_rest in ranked:
        if digest in seen:
            continue
        seen.add(digest)
        ids.append(digest)
        if len(ids) >= _CURSOR_CAP:
            break
    ids.sort()
    current_at = _parse_iso(store["cursor"].get("at") or "")
    if current_at is not None and built_at_dt < current_at:
        return
    if current_at is not None and built_at_dt == current_at:
        union = set(store["cursor"].get("ids") or []) | set(ids)
        merged = ids if len(union) > _CURSOR_CAP else sorted(union)
        if store["cursor"].get("ids") != merged:
            store["cursor"]["ids"] = merged
        return
    store["cursor"] = {"at": _iso(built_at_dt), "ids": ids}


def _add_failure(store: dict, username: str, mac: str, when: datetime, message: str) -> None:
    identity = _identity(username, mac)
    entry = store["entries"].get(identity)
    if entry is None:
        entry = _blank_entry(username, mac)
        store["entries"][identity] = entry
    at = _iso(when)
    cutoff = _cutoff(entry)
    if cutoff and at <= cutoff:
        return
    if cutoff and (entry.get("last") or "") <= cutoff:
        entry["first"] = at
        entry["hours"] = {}
        entry["lines"] = []
    elif not entry.get("first") or at < entry["first"]:
        entry["first"] = at
    if not entry.get("last") or at > entry["last"]:
        entry["last"] = at
    entry["total"] = int(entry.get("total") or 0) + 1
    hour = _hour_key(when)
    entry["hours"][hour] = int(entry["hours"].get(hour) or 0) + 1
    _push_line(entry, at, message)


def _push_line(entry: dict, at: str, message: str) -> None:
    lines = entry["lines"]
    lines.append({"at": at, "message": message})
    lines.sort(key=lambda line: line.get("at") or "")
    if len(lines) > _LINE_KEEP:
        del lines[:-_LINE_KEEP]


def _clear_online(store: dict, users: set[str], macs: set[str], now: datetime) -> None:
    if not users and not macs:
        return
    moment = _iso(now)
    for entry in store["entries"].values():
        if not _is_online(entry.get("username") or "", entry.get("mac") or "", users, macs):
            continue
        cleared = entry.get("cleared") or ""
        last = entry.get("last") or ""
        if cleared and last <= cleared and not entry.get("hours") and not entry.get("lines"):
            continue
        entry["cleared"] = moment
        _drop_hidden(entry, max(entry.get("removed") or "", moment))


def _drop_hidden(entry: dict, cutoff: str) -> None:
    if not cutoff:
        return
    kept = {}
    for key, count in (entry.get("hours") or {}).items():
        start = _hour_start_iso(str(key))
        if start and start > cutoff:
            kept[str(key)] = int(count)
    entry["hours"] = kept
    entry["lines"] = [line for line in entry.get("lines") or [] if str(line.get("at") or "") > cutoff]


def _cutoff(entry: dict) -> str:
    return max(entry.get("removed") or "", entry.get("cleared") or "")


def _prune_store(store: dict, now: datetime) -> None:
    cutoff = _iso(now - timedelta(days=_PRUNE_DAYS))
    earliest = _hour_key(now - timedelta(hours=_HOUR_KEEP))
    latest = _hour_key(now + timedelta(hours=2))
    drop = []
    for key, entry in store["entries"].items():
        last = entry.get("last") or entry.get("removed") or ""
        if not last or last < cutoff:
            drop.append(key)
            continue
        hours = {
            str(hour): int(count)
            for hour, count in (entry.get("hours") or {}).items()
            if earliest <= str(hour) <= latest and _as_int(count) > 0
        }
        if hours != entry.get("hours"):
            entry["hours"] = hours
        lines = [
            {"at": str(line.get("at") or ""), "message": str(line.get("message") or "")[:500]}
            for line in (entry.get("lines") or [])
            if isinstance(line, dict) and str(line.get("at") or "") >= cutoff
        ]
        lines.sort(key=lambda line: line["at"])
        lines = lines[-_LINE_KEEP:]
        if lines != entry.get("lines"):
            entry["lines"] = lines
    for key in drop:
        del store["entries"][key]


def _row(router_id: str, names: dict, entry: dict, moment: datetime, window: set[str], horizon: str) -> dict | None:
    if not isinstance(entry, dict):
        return None
    last = str(entry.get("last") or "")
    if not last or last < horizon:
        return None
    cutoff = _cutoff(entry)
    if cutoff and last <= cutoff:
        return None
    count = 0
    for hour, tally in (entry.get("hours") or {}).items():
        if str(hour) not in window:
            continue
        end = _hour_end_iso(str(hour))
        if cutoff and end and end <= cutoff:
            continue
        count += _as_int(tally)
    lines = []
    ordered = sorted(entry.get("lines") or [], key=lambda line: str(line.get("at") or ""), reverse=True)
    for line in ordered:
        if not isinstance(line, dict):
            continue
        at = str(line.get("at") or "")
        if cutoff and at <= cutoff:
            continue
        lines.append({"time": format_sast(at), "message": line.get("message") or ""})
        if len(lines) >= _LINE_KEEP:
            break
    return {
        "router_id": router_id,
        "site_name": names.get(router_id) or router_id,
        "username": entry.get("username") or "",
        "mac": entry.get("mac") or "",
        "count": count,
        "first_seen": format_sast(entry.get("first") or last),
        "last_seen": format_seen(last, moment),
        "last_at": last,
        "lines": lines,
    }


def _window_hours(now: datetime) -> set[str]:
    end = now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=24)
    stop = end + timedelta(hours=1)
    keys = set()
    hour = start
    while hour <= stop:
        keys.add(_hour_key(hour))
        hour += timedelta(hours=1)
    return keys


def _hour_key(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y%m%d%H")


def _hour_start(key: str) -> datetime | None:
    try:
        return datetime.strptime(str(key), "%Y%m%d%H").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _hour_start_iso(key: str) -> str:
    start = _hour_start(key)
    return _iso(start) if start else ""


def _hour_end_iso(key: str) -> str:
    start = _hour_start(key)
    return _iso(start + timedelta(hours=1)) if start else ""


def _digest(text: str) -> str:
    return hashlib.blake2s(text.encode("utf-8"), digest_size=8).hexdigest()


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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
    text = str(value or "").strip()
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


class _CursorBuild:
    """Newest failure hashes seen while streaming an old store. Bounded."""

    def __init__(self) -> None:
        self.at: datetime | None = None
        self._rows: list[tuple[datetime, str]] = []

    def note(self, when: datetime, digest: str) -> None:
        if self.at is None or when > self.at:
            self.at = when
        self._rows.append((when, digest))
        if len(self._rows) > _CURSOR_CAP * 2:
            self._compact()

    def _compact(self) -> None:
        self._rows.sort(key=lambda item: (item[0], item[1]), reverse=True)
        kept = []
        seen: set[str] = set()
        for item in self._rows:
            if item[1] in seen:
                continue
            seen.add(item[1])
            kept.append(item)
            if len(kept) >= _CURSOR_CAP:
                break
        self._rows = kept

    def export(self) -> dict | None:
        if self.at is None:
            return None
        self._compact()
        ids = sorted({digest for _when, digest in self._rows})
        return {"at": _iso(self.at), "ids": ids}


class _Reader:
    """Pull JSON values from a large pretty-printed file without holding it all."""

    def __init__(self, path: Path) -> None:
        self._fh = path.open("r", encoding="utf-8", errors="replace")
        self._buf = ""
        self._dec = json.JSONDecoder()
        self._eof = False

    def close(self) -> None:
        self._fh.close()

    def _more(self) -> bool:
        if self._eof:
            return False
        chunk = self._fh.read(65536)
        if not chunk:
            self._eof = True
            return False
        if len(self._buf) + len(chunk) > _VALUE_CAP:
            raise ValueError("value too large")
        self._buf += chunk
        return True

    def _skip_ws(self) -> None:
        while True:
            stripped = self._buf.lstrip()
            if stripped:
                self._buf = stripped
                return
            self._buf = ""
            if not self._more():
                return

    def peek(self) -> str:
        self._skip_ws()
        return self._buf[:1]

    def take(self, token: str) -> None:
        self._skip_ws()
        if not self._buf.startswith(token) and self._more():
            self._skip_ws()
        if not self._buf.startswith(token):
            raise ValueError("expected " + token)
        self._buf = self._buf[len(token) :]

    def value(self):
        self._skip_ws()
        while not self._buf:
            if not self._more():
                raise ValueError("unexpected end")
            self._skip_ws()
        if self._buf[0] in "-0123456789":
            while not self._eof and not any(ch in self._buf for ch in ",}] \n\r\t"):
                if not self._more():
                    break
            parsed, end = self._dec.raw_decode(self._buf)
            self._buf = self._buf[end :]
            return parsed
        while True:
            try:
                parsed, end = self._dec.raw_decode(self._buf)
            except json.JSONDecodeError:
                if not self._more():
                    raise
                continue
            self._buf = self._buf[end :]
            return parsed


def _skip_value(reader: _Reader) -> None:
    char = reader.peek()
    if char == "{":
        reader.take("{")
        if reader.peek() == "}":
            reader.take("}")
            return
        while True:
            reader.value()
            reader.take(":")
            _skip_value(reader)
            if reader.peek() == ",":
                reader.take(",")
                if reader.peek() == "}":
                    reader.take("}")
                    return
                continue
            reader.take("}")
            return
    if char == "[":
        reader.take("[")
        if reader.peek() == "]":
            reader.take("]")
            return
        while True:
            _skip_value(reader)
            if reader.peek() == ",":
                reader.take(",")
                if reader.peek() == "]":
                    reader.take("]")
                    return
                continue
            reader.take("]")
            return
    reader.value()


def _read_array(reader: _Reader, on_item) -> None:
    reader.take("[")
    if reader.peek() == "]":
        reader.take("]")
        return
    while True:
        on_item(reader.value())
        char = reader.peek()
        if char == ",":
            reader.take(",")
            if reader.peek() == "]":
                reader.take("]")
                return
            continue
        reader.take("]")
        return


def _walk(path: Path, on_key) -> None:
    reader = _Reader(path)
    try:
        if reader.peek() != "{":
            raise ValueError("not an object")
        reader.take("{")
        if reader.peek() == "}":
            reader.take("}")
            return
        while True:
            key = reader.value()
            reader.take(":")
            on_key(str(key), reader)
            if reader.peek() == ",":
                reader.take(",")
                if reader.peek() == "}":
                    reader.take("}")
                    return
                continue
            reader.take("}")
            return
    finally:
        reader.close()


def _scan_side(path: Path) -> tuple[dict, dict, dict]:
    removed: dict = {}
    cleared: dict = {}
    poll: dict = {}

    def on_key(key: str, reader: _Reader) -> None:
        nonlocal removed, cleared, poll
        if key == "removed":
            found = reader.value()
            if isinstance(found, dict):
                removed = {str(name): str(when) for name, when in found.items()}
        elif key == "cleared":
            found = reader.value()
            if isinstance(found, dict):
                cleared = {str(name): str(when) for name, when in found.items()}
        elif key == "poll":
            found = reader.value()
            if isinstance(found, dict):
                poll = found
        else:
            _skip_value(reader)

    try:
        _walk(path, on_key)
    except Exception:
        return removed, cleared, poll
    return removed, cleared, poll


def _fold_event(store: dict, event: dict, removed: dict, cleared: dict, cursor: _CursorBuild, visible: set[str], now: datetime) -> None:
    if not isinstance(event, dict):
        return
    username = str(event.get("username") or "")
    mac = str(event.get("mac") or "")
    if not username and not mac:
        return
    at = _parse_iso(str(event.get("at") or ""))
    if at is None:
        return
    message = str(event.get("message") or "")[:500]
    key = event.get("key")
    if not isinstance(key, str) or not key:
        key = f"{event.get('time') or ''}\n{message}"
    cursor.note(at, _digest(key))
    if at < now - timedelta(days=_PRUNE_DAYS):
        return
    identity = _identity(username, mac)
    entry = store["entries"].get(identity)
    if entry is None:
        entry = _blank_entry(username, mac)
        entry["removed"] = str(removed.get(identity) or "")
        entry["cleared"] = str(cleared.get(identity) or "")
        store["entries"][identity] = entry
    cutoff = _cutoff(entry)
    stamp = _iso(at)
    if cutoff and stamp <= cutoff:
        entry["total"] = int(entry.get("total") or 0) + 1
        if not entry.get("last") or stamp > entry["last"]:
            entry["last"] = stamp
        if not entry.get("first"):
            entry["first"] = stamp
        return
    fresh = bool(cutoff) and identity not in visible and (not entry.get("last") or entry["last"] <= cutoff)
    if fresh:
        entry["first"] = stamp
        entry["hours"] = {}
        entry["lines"] = []
    elif not entry.get("first") or stamp < entry["first"]:
        entry["first"] = stamp
    visible.add(identity)
    if not entry.get("last") or stamp > entry["last"]:
        entry["last"] = stamp
    entry["total"] = int(entry.get("total") or 0) + 1
    hour = _hour_key(at)
    entry["hours"][hour] = int(entry["hours"].get(hour) or 0) + 1
    _push_line(entry, stamp, message)


def _apply_lone_marks(store: dict, removed: dict, cleared: dict) -> None:
    for identity, when in (removed or {}).items():
        stamp = str(when or "")
        if not stamp:
            continue
        entry = store["entries"].get(str(identity))
        if entry is None:
            username, _sep, mac = str(identity).partition("\n")
            entry = _blank_entry(username, mac)
            entry["removed"] = stamp
            store["entries"][str(identity)] = entry
        elif not entry.get("removed"):
            entry["removed"] = stamp
    for identity, when in (cleared or {}).items():
        entry = store["entries"].get(str(identity))
        if entry is not None and when and not entry.get("cleared"):
            entry["cleared"] = str(when)


def _fold_file(path: Path, removed: dict, cleared: dict, poll: dict, now: datetime) -> dict:
    store = _empty()
    record = _poll_record(poll)
    if record:
        store["poll"] = record
    cursor = _CursorBuild()
    visible: set[str] = set()

    def on_key(key: str, reader: _Reader) -> None:
        if key == "events":
            _read_array(reader, lambda event: _fold_event(store, event, removed, cleared, cursor, visible, now))
        else:
            _skip_value(reader)

    try:
        _walk(path, on_key)
    except Exception:
        if not store["entries"] and cursor.at is None:
            raise
    exported = cursor.export()
    if exported:
        store["cursor"] = exported
    _apply_lone_marks(store, removed, cleared)
    _prune_store(store, now)
    return store


def _marks_only(removed: dict, cleared: dict, poll: dict, now: datetime) -> dict:
    store = _empty()
    record = _poll_record(poll)
    if record:
        store["poll"] = record
    _apply_lone_marks(store, removed, cleared)
    _prune_store(store, now)
    return store


def _migrate_file(path: Path, now: datetime) -> None:
    if not _needs_migration(path):
        return
    removed, cleared, poll = _scan_side(path)
    try:
        store = _fold_file(path, removed, cleared, poll, now)
    except Exception:
        store = _marks_only(removed, cleared, poll, now)
    _save(path.parent.parent, path.stem, store)


def _needs_migration(path: Path) -> bool:
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size == 0:
        return False
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(65536)
    except OSError:
        return False
    lead = head.lstrip()
    if lead.startswith('{"v":2') or lead.startswith('{"v": 2'):
        return False
    if size > 65536:
        return True
    return any(token in head for token in ('"events"', '"seen"', '"cleared"', '"removed"'))


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
    return {"v": _VERSION, "cursor": {"at": "", "ids": []}, "entries": {}, "poll": {}}


def _blank_entry(username: str, mac: str) -> dict:
    return {
        "username": username,
        "mac": mac,
        "total": 0,
        "first": "",
        "last": "",
        "removed": "",
        "cleared": "",
        "hours": {},
        "lines": [],
    }


def _poll_record(poll) -> dict:
    if not isinstance(poll, dict):
        return {}
    at = str(poll.get("at") or "")
    status = str(poll.get("status") or "")
    detail = str(poll.get("detail") or "")[:300]
    if not at and not status and not detail:
        return {}
    return {"at": at, "status": status, "detail": detail}


def _normalize_cursor(cursor) -> dict:
    raw = cursor if isinstance(cursor, dict) else {}
    ids = []
    seen: set[str] = set()
    for item in raw.get("ids") or []:
        text = str(item)
        if text and text not in seen:
            seen.add(text)
            ids.append(text)
        if len(seen) >= _CURSOR_CAP:
            break
    ids.sort()
    return {"at": str(raw.get("at") or ""), "ids": ids}


def _normalize_entry(entry: dict) -> dict:
    hours = {}
    raw_hours = entry.get("hours") if isinstance(entry.get("hours"), dict) else {}
    for key, count in raw_hours.items():
        tally = _as_int(count)
        if tally > 0:
            hours[str(key)] = tally
    if len(hours) > _HOUR_KEEP + 2:
        hours = {key: hours[key] for key in sorted(hours)[-(_HOUR_KEEP + 2) :]}
    lines = []
    for line in entry.get("lines") or []:
        if isinstance(line, dict):
            lines.append({"at": str(line.get("at") or ""), "message": str(line.get("message") or "")[:500]})
    lines.sort(key=lambda line: line["at"])
    return {
        "username": str(entry.get("username") or ""),
        "mac": str(entry.get("mac") or ""),
        "total": max(0, _as_int(entry.get("total"))),
        "first": str(entry.get("first") or ""),
        "last": str(entry.get("last") or ""),
        "removed": str(entry.get("removed") or ""),
        "cleared": str(entry.get("cleared") or ""),
        "hours": hours,
        "lines": lines[-_LINE_KEEP:],
    }


def _normalize(payload) -> dict:
    store = _empty()
    if not isinstance(payload, dict):
        return store
    store["cursor"] = _normalize_cursor(payload.get("cursor"))
    entries = payload.get("entries") if isinstance(payload.get("entries"), dict) else {}
    for key, entry in entries.items():
        if isinstance(entry, dict):
            store["entries"][str(key)] = _normalize_entry(entry)
    record = _poll_record(payload.get("poll"))
    if record:
        store["poll"] = record
    return store


def _load(data_dir: Path, router_id: str) -> dict:
    if not _SAFE_ID.fullmatch(router_id or ""):
        return _empty()
    path = Path(data_dir) / "pppoe-failures" / f"{router_id}.json"
    if not path.is_file():
        return _empty()
    return _read(path)


def _read(path: Path) -> dict:
    with _LOCK:
        if not path.is_file():
            return _empty()
        try:
            st = path.stat()
        except OSError:
            return _empty()
        hit = _CACHE.get(str(path))
        if hit and hit[0] == st.st_mtime_ns and hit[1] == st.st_size:
            return hit[2]
        if _needs_migration(path):
            _migrate_file(path, datetime.now(timezone.utc))
            hit = _CACHE.get(str(path))
            if hit:
                return hit[2]
            try:
                st = path.stat()
            except OSError:
                return _empty()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return _empty()
        store = _normalize(payload)
        try:
            st = path.stat()
        except OSError:
            return store
        _CACHE[str(path)] = (st.st_mtime_ns, st.st_size, store)
        return store


def _save(data_dir: Path, router_id: str, store: dict) -> None:
    path = _path(data_dir, router_id)
    payload = json.dumps(store, separators=(",", ":")) + "\n"
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".pppoe-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)
    st = path.stat()
    _CACHE[str(path)] = (st.st_mtime_ns, st.st_size, copy.deepcopy(store))
    _ROW_CACHE["sig"] = None
