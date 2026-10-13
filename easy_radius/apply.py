"""Back up FreeRADIUS files, write generated config, and restart only if it checks out."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from easy_radius.configgen import render_clients_conf, render_users_file
from easy_radius.hostcmd import CommandResult


@dataclass
class ApplyResult:
    ok: bool
    rolled_back: bool
    restarted: bool
    backup_dir: str
    output: str
    commands: list[CommandResult] = field(default_factory=list)


def _resolve_write_path(path: Path) -> Path:
    path = Path(path)
    if path.is_symlink():
        return path.resolve()
    return path


def _atomic_write(path: Path, text: str) -> None:
    target = _resolve_write_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f".{target.name}.easy-radius-tmp"
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, target)


def _backup(path: Path, dest: Path) -> bool:
    target = _resolve_write_path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.copy2(target, dest)
        return True
    dest.with_name(dest.name + ".missing").write_text("missing\n", encoding="utf-8")
    return False


def _restore(path: Path, backup: Path, existed: bool) -> None:
    target = _resolve_write_path(path)
    if not existed:
        if target.exists():
            target.unlink()
        return
    shutil.copy2(backup, target)


def _fix_permissions(runner, path: Path) -> CommandResult:
    script = (
        'path="$1"; '
        'gid="$(getent group freerad | cut -d: -f3 || true)"; '
        'if [ -n "$gid" ]; then chown "root:$gid" "$path"; '
        'else echo "freerad group not found" >&2; exit 1; fi; '
        'chmod 640 "$path"'
    )
    return runner(["sh", "-c", script, "sh", str(_resolve_write_path(path))])


def apply_configuration(
    state: dict,
    runner,
    clients_path: Path,
    users_path: Path,
    backup_root: Path,
) -> ApplyResult:
    clients_path = Path(clients_path)
    users_path = Path(users_path)
    backup_root = Path(backup_root)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = backup_root / stamp
    notes: list[str] = []
    commands: list[CommandResult] = []

    clients_existed = _backup(clients_path, backup_dir / "clients.conf")
    users_existed = _backup(users_path, backup_dir / "users")
    notes.append(f"Backed up current files to {backup_dir}")

    when = datetime.now(timezone.utc)
    clients_text = render_clients_conf(state["localhost_secret"], state.get("routers") or [], when=when)
    users_text = render_users_file(state.get("users") or [], when=when)
    _atomic_write(clients_path, clients_text)
    _atomic_write(users_path, users_text)
    notes.append(f"Wrote {clients_path}")
    notes.append(f"Wrote {users_path}")

    for path in (clients_path, users_path):
        result = _fix_permissions(runner, path)
        commands.append(result)
        notes.append(result.format())
        if not result.ok:
            return _rollback(
                notes,
                commands,
                clients_path,
                users_path,
                backup_dir,
                clients_existed,
                users_existed,
                "Permissions were not applied. FreeRADIUS was not restarted.",
            )

    check = runner(["freeradius", "-XC"])
    commands.append(check)
    notes.append(check.format())
    if not check.ok:
        return _rollback(
            notes,
            commands,
            clients_path,
            users_path,
            backup_dir,
            clients_existed,
            users_existed,
            "freeradius -XC failed. Restored the previous files. FreeRADIUS was not restarted.",
        )

    restart = runner(["systemctl", "restart", "freeradius"])
    commands.append(restart)
    notes.append(restart.format())
    if not restart.ok:
        return _rollback(
            notes,
            commands,
            clients_path,
            users_path,
            backup_dir,
            clients_existed,
            users_existed,
            "systemctl restart freeradius failed. Restored the previous files.",
        )

    active = runner(["systemctl", "is-active", "freeradius"])
    commands.append(active)
    notes.append(active.format())
    if not active.ok or active.stdout.strip() != "active":
        return _rollback(
            notes,
            commands,
            clients_path,
            users_path,
            backup_dir,
            clients_existed,
            users_existed,
            "FreeRADIUS did not stay active. Restored the previous files.",
        )

    notes.append("FreeRADIUS configuration check passed and the service was restarted.")
    return ApplyResult(
        ok=True,
        rolled_back=False,
        restarted=True,
        backup_dir=str(backup_dir),
        output="\n\n".join(notes),
        commands=commands,
    )


def _rollback(
    notes: list[str],
    commands: list[CommandResult],
    clients_path: Path,
    users_path: Path,
    backup_dir: Path,
    clients_existed: bool,
    users_existed: bool,
    reason: str,
) -> ApplyResult:
    notes.append(reason)
    try:
        _restore(clients_path, backup_dir / "clients.conf", clients_existed)
        _restore(users_path, backup_dir / "users", users_existed)
        notes.append("Previous clients.conf and users file were restored.")
    except OSError as exc:
        notes.append(f"Restore failed: {exc}")
    return ApplyResult(
        ok=False,
        rolled_back=True,
        restarted=False,
        backup_dir=str(backup_dir),
        output="\n\n".join(notes),
        commands=commands,
    )


def run_radtest(username: str, password: str, secret: str, runner) -> CommandResult:
    return runner(["radtest", username, password, "127.0.0.1", "0", secret])
