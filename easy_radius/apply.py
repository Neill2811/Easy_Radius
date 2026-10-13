"""Back up FreeRADIUS files, write generated config, and restart only if it checks out."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from easy_radius.access import render_access_policy
from easy_radius.configgen import render_clients_conf, render_users_file
from easy_radius.hostcmd import CommandResult
from easy_radius.perms import file_permission_args, freeradius_config_check_args, remember


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


def _fix_permissions(runner, path: Path, identity: tuple[int, int, int] | None) -> CommandResult:
    return runner(file_permission_args(path, identity))


def apply_configuration(
    state: dict,
    runner,
    clients_path: Path,
    users_path: Path,
    backup_root: Path,
    policy_path: Path | None = None,
) -> ApplyResult:
    clients_path = Path(clients_path)
    users_path = Path(users_path)
    backup_root = Path(backup_root)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = backup_root / stamp
    notes: list[str] = []
    commands: list[CommandResult] = []
    when = datetime.now(timezone.utc)
    managed = [
        (clients_path, "clients.conf", render_clients_conf(state["localhost_secret"], state.get("routers") or [], when=when)),
        (users_path, "users", render_users_file(state.get("users") or [], when=when)),
    ]
    if policy_path is not None:
        managed.append(
            (
                Path(policy_path),
                "easy_radius",
                render_access_policy(state.get("users") or [], state.get("routers") or [], when=when),
            )
        )

    existed: dict[str, bool] = {}
    identities: dict[str, tuple[int, int, int] | None] = {}
    for path, name, _text in managed:
        identities[name] = remember(path)
        existed[name] = _backup(path, backup_dir / name)
    notes.append(f"Backed up current files to {backup_dir}")

    for path, _name, text in managed:
        _atomic_write(path, text)
        notes.append(f"Wrote {path}")

    def fail(reason: str, restart_restored: bool = False) -> ApplyResult:
        result = _rollback(notes, commands, managed, backup_dir, existed, identities, runner, reason)
        if restart_restored:
            again = runner(["systemctl", "restart", "freeradius"])
            result.commands.append(again)
            extra = again.format()
            if again.ok:
                extra += "\n\nRestarted FreeRADIUS with the restored files."
            else:
                extra += "\n\nRestart of the restored files failed."
            result.output = result.output + "\n\n" + extra
        return result

    for path, name, _text in managed:
        result = _fix_permissions(runner, path, identities[name])
        commands.append(result)
        if result.ok:
            if identities[name] is None:
                notes.append(f"Set freerad:freerad mode 640 on {path}")
            else:
                notes.append(f"Restored the original owner and mode on {path}")
        else:
            notes.append(result.format())
            return fail("Permissions were not applied. FreeRADIUS was not restarted.")

    check = runner(freeradius_config_check_args())
    commands.append(check)
    notes.append(check.format())
    if not check.ok:
        return fail("freeradius -XC as freerad failed. Restored the previous files. FreeRADIUS was not restarted.")

    restart = runner(["systemctl", "restart", "freeradius"])
    commands.append(restart)
    notes.append(restart.format())
    if not restart.ok:
        journal = runner(["journalctl", "-u", "freeradius", "-n", "80", "--no-pager"])
        commands.append(journal)
        notes.append(journal.format())
        return fail("systemctl restart freeradius failed. Restored the previous files.", restart_restored=True)

    active = runner(["systemctl", "is-active", "freeradius"])
    commands.append(active)
    notes.append(active.format())
    if not active.ok or active.stdout.strip() != "active":
        return fail("FreeRADIUS did not stay active. Restored the previous files.", restart_restored=True)

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
    managed: list[tuple[Path, str, str]],
    backup_dir: Path,
    existed: dict[str, bool],
    identities: dict[str, tuple[int, int, int] | None],
    runner,
    reason: str,
) -> ApplyResult:
    notes.append(reason)
    try:
        for path, name, _text in managed:
            _restore(path, backup_dir / name, existed[name])
            if existed[name]:
                fixed = _fix_permissions(runner, path, identities.get(name))
                commands.append(fixed)
                if not fixed.ok:
                    notes.append(fixed.format())
        notes.append("Previous FreeRADIUS files were restored.")
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


def run_radtest(username: str, password: str, secret: str, runner, nas_ip: str = "") -> CommandResult:
    args = ["radtest", username, password, "127.0.0.1", "0", secret]
    if nas_ip:
        args.extend(["0", nas_ip])
    return runner(args)
