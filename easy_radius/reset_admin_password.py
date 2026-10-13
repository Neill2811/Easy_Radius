"""Set a new admin password from the command line.

Used when the password has been lost:

    sudo docker exec -it radius-admin python -m easy_radius.reset_admin_password

The new password is stored only as a hash. Existing browser sessions stop
working because the session key is rotated.
"""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

from easy_radius.audit import record
from easy_radius.store import data_path, initial_password_path, load_state, save_state, set_admin_password


def _data_dir() -> Path:
    configured = os.environ.get("RADIUS_ADMIN_DATA_DIR")
    if configured:
        return Path(configured)
    default = Path("/opt/radius-admin/data")
    if data_path(default).exists():
        return default
    return Path("data")


def main(argv: list[str] | None = None) -> int:
    if argv:
        print("This command does not take arguments. It will prompt for the password.", file=sys.stderr)
        return 2
    data_dir = _data_dir()
    if not data_path(data_dir).exists():
        print(f"No Easy Radius data file at {data_path(data_dir)}.", file=sys.stderr)
        return 1
    first = getpass.getpass("New admin password: ")
    second = getpass.getpass("Repeat new admin password: ")
    if first != second:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    if len(first) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        return 1
    state = load_state(data_dir)
    set_admin_password(state, first)
    record(state, "security", "Reset the admin password from the command line")
    save_state(data_dir, state)
    initial = initial_password_path(data_dir)
    if initial.exists():
        initial.unlink()
    print("Admin password updated. Existing sign-ins will be asked to log in again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
