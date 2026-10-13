"""Ownership for FreeRADIUS files.

The daemon runs as freerad. A root-owned mode 0640 file is unreadable to it,
and `freeradius -XC` as root will not notice. New files are freerad:freerad
0640. Files that already exist keep the owner and mode they had, which on
Ubuntu is freerad:freerad 0640. New directories are freerad:freerad 0750.
"""

from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path


FILE_MODE = 0o640
DIR_MODE = 0o750


class PermError(Exception):
    pass


def freerad_ids() -> tuple[int, int] | None:
    try:
        user = pwd.getpwnam("freerad")
    except KeyError:
        return None
    return user.pw_uid, user.pw_gid


def remember(path: Path) -> tuple[int, int, int] | None:
    """Return uid, gid, and permission bits for an existing file or directory."""
    target = path.resolve() if path.is_symlink() else path
    if not target.exists():
        return None
    info = target.stat()
    return info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)


def _chown(path: Path, uid: int, gid: int) -> None:
    try:
        os.chown(path, uid, gid)
    except PermissionError:
        if os.geteuid() == 0:
            raise PermError(f"Could not chown {path} to {uid}:{gid}") from None
    except OSError as exc:
        if os.geteuid() == 0:
            raise PermError(f"Could not chown {path}: {exc}") from exc


def apply_identity(path: Path, identity: tuple[int, int, int] | None) -> None:
    target = path.resolve() if path.is_symlink() else path
    if identity is None:
        ids = freerad_ids()
        if ids is None:
            if os.geteuid() == 0:
                raise PermError("freerad user not found")
            os.chmod(target, FILE_MODE)
            return
        _chown(target, ids[0], ids[1])
        os.chmod(target, FILE_MODE)
        return
    uid, gid, mode = identity
    _chown(target, uid, gid)
    os.chmod(target, mode)


def ensure_dir(path: Path) -> None:
    """Create a directory, and any missing parents, as freerad:freerad 0750.

    Directories that already exist are left alone so stock modes stay put.
    """
    path = Path(path)
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    ids = freerad_ids()
    for directory in reversed(missing):
        if not directory.is_dir():
            continue
        os.chmod(directory, DIR_MODE)
        if ids is not None:
            _chown(directory, ids[0], ids[1])


def write_text(path: Path, text: str) -> None:
    """Write text, keeping the previous owner and mode when the file exists."""
    path = Path(path)
    target = path.resolve() if path.is_symlink() else path
    identity = remember(target)
    ensure_dir(target.parent)
    tmp = target.parent / f".{target.name}.easy-radius-tmp"
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, target)
    apply_identity(target, identity)


def freeradius_config_check_args() -> list[str]:
    """Same check the freerad service can pass. Root misses permission errors."""
    return ["sudo", "-u", "freerad", "freeradius", "-XC"]


def file_permission_args(path: Path, identity: tuple[int, int, int] | None) -> list[str]:
    """Host command that sets ownership. Used from the container via nsenter."""
    target = str(path.resolve() if path.is_symlink() else path)
    if identity is None:
        script = (
            'path="$1"; '
            'uid="$(id -u freerad)" || { echo "freerad user not found" >&2; exit 1; }; '
            'gid="$(id -g freerad)" || exit 1; '
            'chown "$uid:$gid" "$path" || exit 1; '
            'chmod 640 "$path"'
        )
        return ["sh", "-c", script, "sh", target]
    uid, gid, mode = identity
    script = (
        'path="$1"; uid="$2"; gid="$3"; mode="$4"; '
        'chown "$uid:$gid" "$path" || exit 1; '
        'chmod "$mode" "$path"'
    )
    return ["sh", "-c", script, "sh", target, str(uid), str(gid), format(mode, "o")]
