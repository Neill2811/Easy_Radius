"""Nightly RouterOS exports, retention, and change detection."""

from __future__ import annotations

import difflib
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from easy_radius.audit import record
from easy_radius.automation import AutomationError, account_password

_STAMP = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
_HEADER = re.compile(r"^# \d{4}-\d{2}-\d{2} .+ by RouterOS .+$")


def default_schedule() -> dict:
    return {"enabled": True, "hour": 2, "retention_days": 30, "last_run": ""}


def normalize_export(text: str) -> str:
    lines = text.replace("\r\n", "\n").splitlines()
    if lines and _HEADER.match(lines[0].strip()):
        lines = lines[1:]
    body = "\n".join(line.rstrip() for line in lines).strip()
    return body + ("\n" if body else "")


def backup_dir(data_dir: Path, router_id: str) -> Path:
    path = Path(data_dir) / "router-backups" / router_id
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    os.chmod(path, 0o700)
    return path


def list_versions(data_dir: Path, router_id: str) -> list[str]:
    folder = Path(data_dir) / "router-backups" / router_id
    if not folder.is_dir():
        return []
    stamps = [path.stem for path in folder.glob("*.rsc") if _STAMP.fullmatch(path.stem)]
    return sorted(stamps, reverse=True)


def read_version(data_dir: Path, router_id: str, stamp: str) -> str:
    if not _STAMP.fullmatch(stamp):
        raise AutomationError("Unknown backup")
    path = Path(data_dir) / "router-backups" / router_id / f"{stamp}.rsc"
    if not path.is_file():
        raise AutomationError("Unknown backup")
    return path.read_text(encoding="utf-8", errors="replace")


def diff_versions(older: str, newer: str) -> str:
    diff = difflib.unified_diff(
        normalize_export(older).splitlines(),
        normalize_export(newer).splitlines(),
        fromfile="older",
        tofile="newer",
        lineterm="",
    )
    return "\n".join(diff)


def _touched_since(state: dict, router_id: str, previous_stamp: str) -> bool:
    touches = state.get("router_touches") or {}
    touched = str(touches.get(router_id) or "")
    if not touched or not previous_stamp:
        return False
    # Stamps and touch times are both UTC timestamps that sort as text.
    previous = f"{previous_stamp[0:4]}-{previous_stamp[4:6]}-{previous_stamp[6:8]}T{previous_stamp[9:11]}:{previous_stamp[11:13]}:{previous_stamp[13:15]}Z"
    return touched >= previous


def save_export(data_dir: Path, router: dict, text: str, when: datetime) -> str:
    stamp = when.strftime("%Y%m%dT%H%M%SZ")
    path = backup_dir(data_dir, router["id"]) / f"{stamp}.rsc"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)
    return stamp


def prune(data_dir: Path, router_id: str, retention_days: int, now: datetime) -> int:
    removed = 0
    cutoff = (now - timedelta(days=max(1, retention_days))).strftime("%Y%m%dT%H%M%SZ")
    folder = Path(data_dir) / "router-backups" / router_id
    if not folder.is_dir():
        return 0
    for path in folder.glob("*.rsc"):
        if _STAMP.fullmatch(path.stem) and path.stem < cutoff:
            path.unlink()
            removed += 1
    return removed


def backup_due(schedule: dict, now: datetime) -> bool:
    if not schedule.get("enabled", True):
        return False
    hour = int(schedule.get("hour", 2))
    if now.hour < hour:
        return False
    last = str(schedule.get("last_run") or "")
    return not last.startswith(now.strftime("%Y-%m-%d"))


def explain_backup_error(text: str, password: str = "") -> str:
    """Turn a connection failure into a short reason. The password is never kept."""
    cleaned = _scrub(text or "", password)
    low = cleaned.lower()
    if "connection refused" in low or "errno 111" in low:
        return "connection refused"
    if any(word in low for word in ("handshake", "certificate", "tls", "wrong version number")):
        return "api-ssl has no certificate"
    if any(
        word in low
        for word in (
            "authentication",
            "login failed",
            "bad password",
            "invalid password",
            "invalid user",
            "access denied",
            "cannot log in",
            "rejected",
        )
    ):
        return "service account rejected; check Apply/permissions"
    if "no route" in low:
        return "no route to host"
    if "timed out" in low or "timeout" in low:
        return "timed out"
    return cleaned


def complete_backup(state: dict, data_dir: Path, connector, actor: str, now: datetime | None = None) -> dict:
    """Run backups, keep the per-router result, and advance the schedule."""
    when = now or datetime.now(timezone.utc)
    try:
        result = run_backups(state, data_dir, connector, actor=actor, now=when)
    except AutomationError as exc:
        detail = explain_backup_error(str(exc))
        record(state, "backup", f"Backup failed: {detail}", actor=actor)
        result = {
            "at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": actor,
            "routers": [],
            "error": detail,
        }
    schedule = {**default_schedule(), **(state.get("backup_schedule") or {})}
    schedule["last_run"] = result["at"]
    state["backup_schedule"] = schedule
    state["last_backup_run"] = {
        "at": result["at"],
        "actor": result.get("actor") or actor,
        "error": result.get("error") or "",
        "routers": [
            {
                "id": item.get("id") or "",
                "site_name": item.get("site_name") or "",
                "status": item.get("status") or "failed",
                "detail": item.get("detail") or "",
                "stamp": item.get("stamp") or "",
            }
            for item in result.get("routers") or []
        ],
    }
    return state["last_backup_run"]


def run_backups(state: dict, data_dir: Path, connector, actor: str, now: datetime | None = None) -> dict:
    when = now or datetime.now(timezone.utc)
    username, password = account_password(state)
    alerts = []
    done = []
    for router in state.get("routers") or []:
        if router.get("enabled", True) is False:
            continue
        previous = list_versions(data_dir, router["id"])
        previous_stamp = previous[0] if previous else ""
        previous_text = read_version(data_dir, router["id"], previous_stamp) if previous_stamp else ""
        try:
            session = _open(connector, router, username, password)
        except Exception as exc:
            _failed(state, done, router, exc, password, actor)
            continue
        try:
            text = session.export()
        except Exception as exc:
            _failed(state, done, router, exc, password, actor)
            continue
        finally:
            close = getattr(session, "close", None)
            if close:
                try:
                    close()
                except Exception:
                    pass
        stamp = save_export(data_dir, router, text, when)
        changed = bool(previous_text) and normalize_export(previous_text) != normalize_export(text)
        outside = changed and not _touched_since(state, router["id"], previous_stamp)
        if outside:
            alerts.append(
                {
                    "at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "router_id": router["id"],
                    "site_name": router["site_name"],
                    "stamp": stamp,
                    "previous": previous_stamp,
                }
            )
            record(
                state,
                "backup.change",
                f"Config on {router['site_name']} changed outside Easy Radius",
                actor=actor,
            )
        else:
            record(
                state,
                "backup",
                f"Saved config export for {router['site_name']}" + (" (changed)" if changed else " (unchanged)"),
                actor=actor,
            )
        prune(data_dir, router["id"], int((state.get("backup_schedule") or {}).get("retention_days") or 30), when)
        done.append(
            {
                "id": router["id"],
                "site_name": router["site_name"],
                "status": "changed" if changed else "ok",
                "outside": outside,
                "stamp": stamp,
            }
        )
    state.setdefault("change_alerts", [])
    state["change_alerts"] = (alerts + list(state.get("change_alerts") or []))[:100]
    return {"at": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "actor": actor, "routers": done}


def _failed(state: dict, done: list, router: dict, exc: Exception, password: str, actor: str) -> None:
    detail = explain_backup_error(str(exc), password)
    done.append({"id": router["id"], "site_name": router["site_name"], "status": "failed", "detail": detail})
    record(state, "backup", f"Backup failed for {router['site_name']}: {detail}", actor=actor)


def _open(connector, router, username, password):
    allow = bool(router.get("api_plaintext"))
    try:
        return connector(router["ip"], username, password, allow_plaintext=allow)
    except TypeError:
        return connector(router["ip"], username, password)


def _scrub(text: str, password: str) -> str:
    if password and password in text:
        return text.replace(password, "<password>")
    return text
