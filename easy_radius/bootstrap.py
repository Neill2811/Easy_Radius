"""Prepare the data directory and, on a new server, the starter FreeRADIUS files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from easy_radius.access import render_access_policy
from easy_radius.configgen import render_clients_conf, render_users_file
from easy_radius.perms import write_text
from easy_radius.store import prepare_state


def write_starter(data_dir: Path, clients_path: Path, users_path: Path, policy_path: Path | None = None) -> None:
    state = prepare_state(data_dir, ensure_admin=False)
    clients_path = Path(clients_path)
    users_path = Path(users_path)
    write_text(clients_path, render_clients_conf(state["localhost_secret"], []))
    write_text(users_path, render_users_file([]))
    if policy_path is not None:
        write_text(Path(policy_path), render_access_policy([], []))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare Easy Radius data and optional starter config.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--write-starter", action="store_true")
    parser.add_argument("--clients-conf", default="/etc/freeradius/3.0/clients.conf")
    parser.add_argument(
        "--users-file",
        default="/etc/freeradius/3.0/mods-config/files/authorize",
    )
    parser.add_argument("--policy-file", default="")
    args = parser.parse_args(argv)
    data_dir = Path(args.data_dir)
    if args.write_starter:
        policy = Path(args.policy_file) if args.policy_file else None
        write_starter(data_dir, Path(args.clients_conf), Path(args.users_file), policy)
    else:
        prepare_state(data_dir, ensure_admin=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
