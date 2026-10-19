"""RouterOS version, hardware, and upgrade helpers.

The plaintext API port is used only when the router has opted in. On a
build that does not know that flag yet, the existing connection is used.
"""

from __future__ import annotations

import os
import re
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CHANNELS = ("stable", "long-term", "testing", "development")
LATEST_URL = "https://upgrade.mikrotik.com/routeros/NEWESTa7.stable"
_VERSION = re.compile(r"^\d+(?:\.\d+)+")


def latest_url(channel: str) -> str:
    if channel not in CHANNELS:
        raise ValueError("Unknown firmware channel")
    if channel == "stable":
        return LATEST_URL
    return f"https://upgrade.mikrotik.com/routeros/NEWESTa7.{channel}"


def latest_by_channel(state: dict) -> dict[str, str]:
    """Per-channel latest versions. A legacy single string is the stable version."""
    found = {name: "" for name in CHANNELS}
    raw = state.get("firmware_latest")
    if isinstance(raw, str):
        found["stable"] = raw.strip()
    elif isinstance(raw, dict):
        for name in CHANNELS:
            found[name] = str(raw.get(name) or "").strip()
    return found


def parse_version(text: str | None) -> tuple[int, ...] | None:
    raw = "" if text is None else str(text).strip()
    if not raw:
        return None
    token = raw.split()[0]
    if not _VERSION.match(token):
        return None
    return tuple(int(part) for part in token.split("."))


def version_label(text: str | None) -> str:
    raw = "" if text is None else str(text).strip()
    if parse_version(raw) is None:
        return "unknown"
    return raw


def outdated(installed: str | None, latest: str | None) -> bool:
    left = parse_version(installed)
    right = parse_version(latest)
    if left is None or right is None:
        return False
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) < right + (0,) * (width - len(right))


def fetch_latest(channel: str, opener=None) -> str:
    open_url = opener or urllib.request.urlopen
    with open_url(latest_url(channel), timeout=10) as response:
        text = response.read(200).decode("utf-8", "replace")
    parts = text.split()
    version = parts[0].strip() if parts else ""
    if not _VERSION.match(version):
        raise ValueError("Upstream version was not recognised")
    return version


def fetch_latest_stable(opener=None) -> str:
    return fetch_latest("stable", opener)


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


def read_facts(session) -> dict:
    resource = session.get("/system/resource")
    board = {}
    licence = {}
    if hasattr(session, "get"):
        try:
            board = session.get("/system/routerboard")
        except Exception:
            board = {}
        try:
            licence = session.get("/system/license")
        except Exception:
            licence = {}
    channel = ""
    if hasattr(session, "get"):
        try:
            channel = str(session.get("/system/package/update").get("channel") or "").strip()
        except Exception:
            channel = ""
    total = _int(resource.get("total-memory"))
    free = _int(resource.get("free-memory"))
    used = ""
    if total and free is not None and total > 0:
        used = str(round((total - free) * 100 / total))
    return {
        "version": str(resource.get("version") or ""),
        "channel": channel,
        "model": str(board.get("model") or resource.get("board-name") or ""),
        "arch": str(resource.get("architecture-name") or ""),
        "uptime": str(resource.get("uptime") or ""),
        "serial": str(board.get("serial-number") or ""),
        "licence": str(licence.get("level") or licence.get("nlevel") or ""),
        "routerboard": str(board.get("routerboard") or ""),
        "current_firmware": str(board.get("current-firmware") or ""),
        "upgrade_firmware": str(board.get("upgrade-firmware") or ""),
        "cpu": str(resource.get("cpu-load") or ""),
        "memory_used_pct": used,
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _int(value) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def refresh_router(router, connector, username, password) -> dict:
    session = _open(connector, router, username, password)
    try:
        facts = read_facts(session)
    finally:
        if getattr(session, "close", None):
            session.close()
    router["facts"] = facts
    return facts


def save_upgrade_export(data_dir: Path, router_id: str, text: str, when: datetime) -> None:
    folder = Path(data_dir) / "firmware-backups" / router_id
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder.parent, 0o700)
    os.chmod(folder, 0o700)
    path = folder / f"{when.strftime('%Y%m%dT%H%M%SZ')}.rsc"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def upgrade_router(
    router,
    connector,
    username,
    password,
    data_dir: Path,
    when: datetime | None = None,
    channel: str | None = None,
    routerboard: bool = True,
    wait_seconds: int = 600,
    sleep=None,
    clock=None,
) -> dict:
    moment = when or datetime.now(timezone.utc)
    pause = sleep or time.sleep
    ticks = clock or time.monotonic
    session = _open(connector, router, username, password)
    try:
        text = session.export()
        save_upgrade_export(data_dir, router["id"], text, moment)
        chosen = (channel or "").strip()
        if chosen:
            if chosen not in CHANNELS:
                return _upgrade_result("failed", "Unknown firmware channel.", "failed", "not started")
            session.call("/system/package/update", "set", channel=chosen)
        session.call("/system/package/update", "check-for-updates")
        try:
            session.call("/system/package/update", "install")
        except Exception as exc:
            if not _reboot_drop(exc, password):
                return _upgrade_result("failed", _scrub(str(exc), password), "failed", "not started")
    except Exception as exc:
        return _upgrade_result("failed", _scrub(str(exc), password), "failed", "not started")
    finally:
        _close(session)

    try:
        session = _wait_back(router, connector, username, password, wait_seconds, pause, ticks)
    except TimeoutError as exc:
        return _upgrade_result("failed", f"Router did not come back after the RouterOS install. {exc}", "failed", "not started")
    try:
        resource = session.get("/system/resource") if hasattr(session, "get") else {}
        version = str((resource or {}).get("version") or "").strip()
        routeros = f"confirmed {version}" if version else "confirmed"
        if not routerboard:
            return _upgrade_result("ok", f"RouterOS {routeros}.", routeros, "skipped")
        try:
            board = session.get("/system/routerboard") if hasattr(session, "get") else {}
        except Exception:
            board = {}
        if not _routerboard_applicable(resource or {}, board or {}):
            return _upgrade_result("ok", f"RouterOS {routeros}. RouterBOARD firmware is not applicable.", routeros, "not applicable")
        current = str((board or {}).get("current-firmware") or "").strip()
        upgrade = str((board or {}).get("upgrade-firmware") or "").strip()
        if not upgrade or _same_firmware(current, upgrade):
            return _upgrade_result(
                "ok",
                f"RouterOS {routeros}. RouterBOARD firmware is already {current or 'current'}.",
                routeros,
                "already current",
                current,
                upgrade,
            )
        try:
            session.call("/system/routerboard", "upgrade")
            try:
                session.call("/system", "reboot")
            except Exception as exc:
                if not _reboot_drop(exc, password):
                    return _upgrade_result("failed", _scrub(str(exc), password), routeros, "failed", current, upgrade)
        except Exception as exc:
            return _upgrade_result("failed", _scrub(str(exc), password), routeros, "failed", current, upgrade)
    finally:
        _close(session)

    try:
        session = _wait_back(router, connector, username, password, wait_seconds, pause, ticks)
    except TimeoutError as exc:
        return _upgrade_result("failed", f"Router did not come back after the RouterBOARD upgrade. {exc}", routeros, "failed", current, upgrade)
    try:
        board = session.get("/system/routerboard") if hasattr(session, "get") else {}
        resource = session.get("/system/resource") if hasattr(session, "get") else {}
        version = str((resource or {}).get("version") or version).strip()
        routeros = f"confirmed {version}" if version else routeros
        now_current = str((board or {}).get("current-firmware") or "").strip()
        now_upgrade = str((board or {}).get("upgrade-firmware") or upgrade).strip()
        if _same_firmware(now_current, now_upgrade) and now_current:
            return _upgrade_result("ok", f"RouterOS {routeros}. RouterBOARD firmware {now_current}.", routeros, f"upgraded to {now_current}", now_current, now_upgrade)
        return _upgrade_result(
            "failed",
            f"RouterBOARD firmware is {now_current or 'unknown'}, upgrade firmware is {now_upgrade or 'unknown'}.",
            routeros,
            "failed",
            now_current,
            now_upgrade,
        )
    finally:
        _close(session)


def upgrade_many(
    routers,
    connector,
    username,
    password,
    data_dir: Path,
    batch: int = 1,
    channel: str | None = None,
    routerboard: bool = True,
    wait_seconds: int = 600,
    sleep=None,
    clock=None,
) -> list[dict]:
    results = []
    stopped = False
    size = max(1, min(int(batch or 1), 50))
    pending = list(routers)
    while pending:
        wave, pending = pending[:size], pending[size:]
        for router in wave:
            if stopped:
                results.append(_skipped(router))
                continue
            try:
                outcome = upgrade_router(
                    router,
                    connector,
                    username,
                    password,
                    data_dir,
                    channel=channel,
                    routerboard=routerboard,
                    wait_seconds=wait_seconds,
                    sleep=sleep,
                    clock=clock,
                )
            except Exception as exc:
                outcome = _upgrade_result("failed", _scrub(str(exc), password), "failed", "not started")
            results.append({"id": router["id"], "site_name": router["site_name"], **outcome})
            if outcome["status"] == "failed":
                stopped = True
        if stopped:
            results.extend(_skipped(router) for router in pending)
            break
    return results


def _upgrade_result(status: str, detail: str, routeros: str, routerboard: str, current: str = "", upgrade: str = "") -> dict:
    return {
        "status": status,
        "detail": detail,
        "routeros": routeros,
        "routerboard": routerboard,
        "current_firmware": current,
        "upgrade_firmware": upgrade,
    }


def _routerboard_applicable(resource: dict, board: dict) -> bool:
    arch = str(resource.get("architecture-name") or "").lower()
    if arch in {"x86", "x86_64"}:
        return False
    name = str(board.get("model") or board.get("board-name") or resource.get("board-name") or "").lower()
    if "chr" in name:
        return False
    return str(board.get("routerboard") or "").strip().lower() in {"yes", "true"}


def _same_firmware(current: str, upgrade: str) -> bool:
    if current.strip() == upgrade.strip():
        return True
    left = parse_version(current)
    right = parse_version(upgrade)
    return left is not None and left == right


def _reboot_drop(exc: Exception, password: str) -> bool:
    message = _scrub(str(exc), password).lower()
    return any(word in message for word in ("timed out", "timeout", "connection", "reset", "closed"))


def _wait_back(router, connector, username, password, timeout: int, sleep, clock):
    started = clock()
    deadline = started + max(0, int(timeout))
    error = "timed out"
    while True:
        session = None
        try:
            session = _open(connector, router, username, password)
            if hasattr(session, "get"):
                session.get("/system/resource")
            return session
        except Exception as exc:
            error = _scrub(str(exc), password) or error
            _close(session)
            if clock() >= deadline:
                raise TimeoutError(error) from exc
            remaining = deadline - clock()
            sleep(2 if remaining > 2 else max(0, remaining))


def _close(session) -> None:
    if getattr(session, "close", None):
        try:
            session.close()
        except Exception:
            pass


def _skipped(router) -> dict:
    return {
        "id": router["id"],
        "site_name": router["site_name"],
        "status": "skipped",
        "detail": "Not started. An earlier router failed.",
    }
