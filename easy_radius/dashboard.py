"""Dashboard figures from saved state and log files.

Nothing here opens a RouterOS session. FreeRADIUS is checked with the
local service command. Times are shown in South African Standard Time.
"""

from __future__ import annotations

import shutil
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from easy_radius.compliance import router_compliant
from easy_radius.facts import CHANNELS, latest_by_channel, outdated, version_label
from easy_radius.logs import packet_times, router_health

SAST = ZoneInfo("Africa/Johannesburg")


def format_sast(value) -> str:
    moment = _as_sast(value)
    if moment is None:
        return ""
    return moment.strftime("%Y-%m-%d %H:%M SAST")


def build_dashboard(
    state: dict,
    auth_events: list[dict],
    acct_events: list[dict],
    *,
    now: int,
    health_seconds: int,
    data_dir: Path,
    runner,
) -> dict:
    routers = [router for router in (state.get("routers") or []) if isinstance(router, dict)]
    health = {
        row["id"]: row
        for row in router_health(routers, packet_times(auth_events, acct_events), now, health_seconds)
    }
    names = {router.get("id"): router.get("site_name") or router.get("id") for router in routers}
    by_ip = {str(router.get("ip") or ""): router.get("site_name") or router.get("ip") for router in routers}
    return {
        "routers": _router_counts(routers, health),
        "compliance": _compliance(state),
        "backup": _config_backup(state),
        "alerts": _alerts(state),
        "attention": _attention(routers, health, names, state, data_dir, now),
        "logins": _logins(auth_events, now, state, by_ip),
        "activity": _activity(state),
        "grants": _grants(state, now, names),
        "firmware": _firmware(routers, state),
        "server": {
            "freeradius": _freeradius(runner),
            "disk": _disk_free(data_dir),
            "backup": _app_backup(state),
        },
    }


def _as_sast(value) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(int(value), SAST)
    text = str(value).strip()
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
    return moment.astimezone(SAST)


def _router_counts(routers: list[dict], health: dict) -> dict:
    up = down = unseen = 0
    for router in routers:
        row = health.get(router.get("id"), {})
        if row.get("up"):
            up += 1
        elif row.get("age") is None:
            unseen += 1
        else:
            down += 1
    return {"up": up, "down": down, "unseen": unseen, "total": len(routers), "empty": not routers}


def _compliance(state: dict) -> dict:
    report = state.get("last_compliance")
    if not isinstance(report, dict) or not report.get("routers"):
        return {"known": False, "compliant": 0, "total": 0}
    rows = [row for row in report.get("routers") or [] if isinstance(row, dict)]
    compliant = sum(1 for row in rows if router_compliant(row))
    return {"known": True, "compliant": compliant, "total": len(rows)}


def _config_backup(state: dict) -> dict:
    run = state.get("last_backup_run")
    if not isinstance(run, dict) or not run.get("at"):
        return {"known": False, "ok": 0, "failed": 0, "when": "", "error": ""}
    ok = failed = 0
    for row in run.get("routers") or []:
        if not isinstance(row, dict):
            continue
        if row.get("status") == "failed":
            failed += 1
        else:
            ok += 1
    return {
        "known": True,
        "ok": ok,
        "failed": failed,
        "when": format_sast(run.get("at")),
        "error": str(run.get("error") or ""),
    }


def _alerts(state: dict) -> dict:
    alerts = [alert for alert in (state.get("monitor_alerts") or []) if isinstance(alert, dict)]
    return {"count": len(alerts), "items": [{"detail": str(alert.get("detail") or "Alert")} for alert in alerts[:5]]}


def _attention(routers: list[dict], health: dict, names: dict, state: dict, data_dir: Path, now: int) -> list[dict]:
    items = []
    for router in routers:
        row = health.get(router.get("id"), {})
        if row.get("age") is not None and not row.get("up"):
            items.append(
                {
                    "title": names.get(router.get("id")) or "Router",
                    "reason": "No recent RADIUS packet",
                    "endpoint": "routers",
                }
            )
    report = state.get("last_compliance")
    if isinstance(report, dict):
        for row in report.get("routers") or []:
            if not isinstance(row, dict) or router_compliant(row):
                continue
            if row.get("error"):
                reason = str(row["error"])
            else:
                failed = next((check for check in (row.get("checks") or []) if isinstance(check, dict) and not check.get("passed")), None)
                if failed:
                    reason = f"{failed.get('title')}: {failed.get('detail')}"
                else:
                    reason = f"{row.get('passed', 0)}/{row.get('total', 0)} checks passed"
            items.append({"title": row.get("site_name") or "Router", "reason": reason, "endpoint": "compliance"})
    run = state.get("last_backup_run") if isinstance(state.get("last_backup_run"), dict) else {}
    listed_failure = False
    for row in run.get("routers") or []:
        if isinstance(row, dict) and row.get("status") == "failed":
            listed_failure = True
            items.append(
                {
                    "title": row.get("site_name") or "Router",
                    "reason": row.get("detail") or "Config backup failed",
                    "endpoint": "config_backups",
                }
            )
    if run.get("error") and not listed_failure:
        items.append({"title": "Config backups", "reason": str(run["error"]), "endpoint": "config_backups"})
    latest = latest_by_channel(state)
    for router in routers:
        facts = router.get("facts") if isinstance(router.get("facts"), dict) else {}
        version = version_label(facts.get("version"))
        channel = str(facts.get("channel") or "").strip()
        name = router.get("site_name") or "Router"
        if version == "unknown" and channel not in CHANNELS:
            items.append({"title": name, "reason": "Version and channel are unknown", "endpoint": "firmware"})
            continue
        if version == "unknown":
            items.append({"title": name, "reason": "Version is unknown", "endpoint": "firmware"})
            continue
        if channel not in CHANNELS:
            items.append({"title": name, "reason": "Channel is unknown", "endpoint": "firmware"})
            continue
        current = latest.get(channel) or ""
        if outdated(facts.get("version"), current):
            items.append(
                {
                    "title": name,
                    "reason": f"{version} is behind {current} on {channel}",
                    "endpoint": "firmware",
                }
            )
    from easy_radius.pppoe_failures import attention_lines

    items.extend(attention_lines(data_dir, state, now))
    return items[:40]


def _logins(auth_events: list[dict], now: int, state: dict, by_ip: dict) -> dict:
    settings = state.get("monitor_settings") if isinstance(state.get("monitor_settings"), dict) else {}
    try:
        minutes = max(1, int(settings.get("reject_minutes") or 10))
        threshold = max(1, int(settings.get("reject_count") or 10))
    except (TypeError, ValueError):
        minutes, threshold = 10, 10
    end = datetime.fromtimestamp(now, SAST).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=23)
    start_ts = int(start.timestamp())
    accept = reject = 0
    hours = []
    for offset in range(24):
        moment = start + timedelta(hours=offset)
        hours.append(
            {
                "label": moment.strftime("%H") if moment.hour % 6 == 0 else "",
                "accept": 0,
                "reject": 0,
            }
        )
    for event in auth_events:
        when = int(event.get("time") or 0)
        if when < start_ts or when > now:
            continue
        slot = int((datetime.fromtimestamp(when, SAST) - start).total_seconds() // 3600)
        if slot < 0 or slot > 23:
            continue
        if event.get("result") == "Access-Accept":
            accept += 1
            hours[slot]["accept"] += 1
        elif event.get("result") == "Access-Reject":
            reject += 1
            hours[slot]["reject"] += 1
    peak = max((max(hour["accept"], hour["reject"]) for hour in hours), default=0)
    for hour in hours:
        hour["accept_h"] = _bar(hour["accept"], peak)
        hour["reject_h"] = _bar(hour["reject"], peak)
    return {
        "accept": accept,
        "reject": reject,
        "hours": hours,
        "empty": accept == 0 and reject == 0,
        "bursts": _bursts(auth_events, now, minutes, threshold, by_ip),
        "burst_window": minutes,
    }


def _bar(count: int, peak: int) -> int:
    if count <= 0 or peak <= 0:
        return 0
    return max(2, round(count / peak * 46))


def _bursts(events: list[dict], now: int, minutes: int, threshold: int, by_ip: dict) -> list[dict]:
    cutoff = now - minutes * 60
    users: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    for event in events:
        if event.get("result") != "Access-Reject":
            continue
        if int(event.get("time") or 0) < cutoff:
            continue
        users[str(event.get("user") or "(unknown)")] += 1
        nas = str(event.get("nas") or "")
        if nas:
            sources[nas] += 1
    found = []
    for user, count in users.most_common():
        if count >= threshold:
            found.append({"kind": "user", "label": user, "count": count})
    for nas, count in sources.most_common():
        if count >= threshold:
            found.append({"kind": "source", "label": by_ip.get(nas) or nas, "count": count})
    return found


def _activity(state: dict) -> list[dict]:
    events = [event for event in (state.get("audit") or []) if isinstance(event, dict)]
    recent = list(reversed(events[-10:]))
    return [
        {
            "when": format_sast(event.get("at")),
            "actor": event.get("actor") or "",
            "detail": event.get("detail") or event.get("action") or "",
        }
        for event in recent
    ]


def _grants(state: dict, now: int, names: dict) -> list[dict]:
    moment = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    active = []
    for grant in state.get("grants") or []:
        if not isinstance(grant, dict):
            continue
        if str(grant.get("expires_at") or "") <= moment:
            continue
        parts = [names.get(router_id) or router_id for router_id in (grant.get("router_ids") or [])]
        parts.extend(grant.get("tags") or [])
        active.append(
            {
                "username": grant.get("username") or "user",
                "until": format_sast(grant.get("expires_at")),
                "what": ", ".join(str(part) for part in parts if part) or "extra access",
            }
        )
    return active


def _firmware(routers: list[dict], state: dict) -> dict:
    latest = latest_by_channel(state)
    groups: Counter[tuple[str, str]] = Counter()
    behind = unknown = 0
    for router in routers:
        facts = router.get("facts") if isinstance(router.get("facts"), dict) else {}
        version = version_label(facts.get("version"))
        channel = str(facts.get("channel") or "").strip() or "unknown"
        groups[(version, channel)] += 1
        if version == "unknown" or channel not in CHANNELS:
            unknown += 1
            continue
        if outdated(facts.get("version"), latest.get(channel) or ""):
            behind += 1
    rows = [
        {"version": version, "channel": channel, "count": count}
        for (version, channel), count in sorted(groups.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    ]
    return {"rows": rows, "behind": behind, "unknown": unknown, "empty": not routers}


def _freeradius(runner) -> str:
    if runner is None:
        return "Not checked"
    try:
        result = runner(["systemctl", "is-active", "freeradius"], timeout=10)
    except TypeError:
        try:
            result = runner(["systemctl", "is-active", "freeradius"])
        except Exception:
            return "Not checked"
    except Exception:
        return "Not checked"
    text = str(getattr(result, "stdout", "") or "").strip()
    word = text.split()[0] if text else ""
    if getattr(result, "returncode", 1) == 0 and word == "active":
        return "Running"
    return word or "Not running"


def _disk_free(data_dir: Path) -> str:
    try:
        free = shutil.disk_usage(data_dir).free
    except OSError:
        return "Unknown"
    gib = free / (1024 ** 3)
    if gib >= 1:
        return f"{gib:.1f} GB free"
    return f"{free / (1024 ** 2):.0f} MB free"


def _app_backup(state: dict) -> str:
    latest = ""
    for event in state.get("audit") or []:
        if not isinstance(event, dict):
            continue
        if event.get("action") == "backup" and "encrypted backup" in str(event.get("detail") or "").lower():
            stamp = str(event.get("at") or "")
            if stamp >= latest:
                latest = stamp
    return format_sast(latest)
