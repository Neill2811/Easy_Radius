"""Prepare the data directory and, on a new server, the starter FreeRADIUS files."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from easy_radius.configgen import render_clients_conf, render_users_file
from easy_radius.store import prepare_state


def _chown_freerad(path: Path) -> None:
    script = (
        'path="$1"; '
        'gid="$(getent group freerad | cut -d: -f3 || true)"; '
        'if [ -n "$gid" ]; then chown "root:$gid" "$path"; fi; '
        'chmod 640 "$path"'
    )
    subprocess.run(["sh", "-c", script, "sh", str(path)], check=False)


def write_starter(data_dir: Path, clients_path: Path, users_path: Path) -> None:
    state = prepare_state(data_dir, ensure_admin=False)
    clients_path = Path(clients_path)
    users_path = Path(users_path)
    clients_path.parent.mkdir(parents=True, exist_ok=True)
    users_path.parent.mkdir(parents=True, exist_ok=True)
    clients_path.write_text(
        render_clients_conf(state["localhost_secret"], []),
        encoding="utf-8",
    )
    users_path.write_text(render_users_file([]), encoding="utf-8")
    for path in (clients_path, users_path):
        os.chmod(path, 0o640)
        _chown_freerad(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare Easy Radius data and optional starter config.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--write-starter", action="store_true")
    parser.add_argument("--clients-conf", default="/etc/freeradius/3.0/clients.conf")
    parser.add_argument(
        "--users-file",
        default="/etc/freeradius/3.0/mods-config/files/authorize",
    )
    args = parser.parse_args(argv)
    data_dir = Path(args.data_dir)
    if args.write_starter:
        write_starter(data_dir, Path(args.clients_conf), Path(args.users_file))
    else:
        prepare_state(data_dir, ensure_admin=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
