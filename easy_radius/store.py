"""JSON data directory for Easy Radius.

Router secrets stay in this file because FreeRADIUS needs them. RADIUS user
passwords and the admin password are stored only as hashes. The directory is
created mode 0700 and the JSON file mode 0600.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path

from easy_radius.configgen import rewrite_cleartext_passwords
from easy_radius.userhash import migrate_users

PBKDF2_ITERATIONS = 200_000
ADMIN_USERNAME = "neill"


class StoreError(Exception):
    pass


def _umask_dir(path: Path) -> None:
    old = os.umask(0o077)
    try:
        path.mkdir(parents=True, exist_ok=True)
    finally:
        os.umask(old)
    os.chmod(path, 0o700)


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations_s, salt_hex, digest_hex = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def _empty_state() -> dict:
    return {
        "secret_key": "",
        "admin_password_hash": "",
        "initial_password_shown": False,
        "localhost_secret": "",
        "routers": [],
        "users": [],
        "audit": [],
        "radius_server_address": "",
        "totp_secret": "",
        "totp_pending_secret": "",
        "totp_enabled": False,
        "last_apply": None,
        "last_test": None,
    }


def data_path(data_dir: Path) -> Path:
    return Path(data_dir) / "data.json"


def initial_password_path(data_dir: Path) -> Path:
    return Path(data_dir) / "initial-admin-password.txt"


def load_state(data_dir: Path) -> dict:
    path = data_path(data_dir)
    if not path.exists():
        return _empty_state()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StoreError(f"Could not read {path}: {exc}") from exc
    state = _empty_state()
    if isinstance(raw, dict):
        state.update(raw)
    state["routers"] = list(state.get("routers") or [])
    state["users"] = list(state.get("users") or [])
    state["audit"] = list(state.get("audit") or [])
    state["radius_server_address"] = state.get("radius_server_address") or ""
    state["totp_secret"] = state.get("totp_secret") or ""
    state["totp_pending_secret"] = state.get("totp_pending_secret") or ""
    state["totp_enabled"] = bool(state.get("totp_enabled"))
    for item in state["routers"]:
        item["enabled"] = bool(item.get("enabled", True))
        item["tags"] = _name_list(item.get("tags"))
    for item in state["users"]:
        item["enabled"] = bool(item.get("enabled", True))
        item["access"] = "routers" if item.get("access") == "routers" else "all"
        item["router_ids"] = [str(value) for value in (item.get("router_ids") or [])]
        item["access_tags"] = _name_list(item.get("access_tags"))
    if migrate_users(state["users"]):
        save_state(data_dir, state)
    return state


def _name_list(value) -> list[str]:
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return []
    names = []
    for item in value:
        text = str(item).strip()
        if text and text not in names:
            names.append(text)
    return names


def save_state(data_dir: Path, state: dict) -> None:
    data_dir = Path(data_dir)
    _umask_dir(data_dir)
    migrate_users(state.get("users") or [])
    path = data_path(data_dir)
    payload = json.dumps(state, indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(dir=data_dir, prefix=".data-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def _write_initial_password(data_dir: Path, password: str) -> None:
    path = initial_password_path(data_dir)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(
            "Easy Radius initial admin password for user 'neill'.\n"
            "This file is created once. Remove it after you have stored the password.\n"
            f"{password}\n"
        )
    os.chmod(path, 0o600)


def _print_initial_password(password: str) -> None:
    banner = "=" * 64
    print(banner, flush=True)
    print("Easy Radius initial admin login (shown once)", flush=True)
    print("Username: neill", flush=True)
    print(f"Password: {password}", flush=True)
    print(banner, flush=True)


def prepare_state(
    data_dir: Path,
    admin_password: str | None = None,
    ensure_admin: bool = True,
) -> dict:
    """Create missing secrets. Print the admin password only on first creation."""
    data_dir = Path(data_dir)
    _umask_dir(data_dir)
    state = load_state(data_dir)
    changed = False
    if not state.get("secret_key"):
        state["secret_key"] = secrets.token_hex(32)
        changed = True
    if not state.get("localhost_secret"):
        state["localhost_secret"] = secrets.token_hex(16)
        changed = True
    if ensure_admin and not state.get("admin_password_hash"):
        password = admin_password or secrets.token_urlsafe(18)
        state["admin_password_hash"] = hash_password(password)
        state["initial_password_shown"] = True
        changed = True
        save_state(data_dir, state)
        _write_initial_password(data_dir, password)
        if admin_password is None:
            _print_initial_password(password)
        upgrade_password_storage(data_dir)
        return state
    if changed:
        save_state(data_dir, state)
    upgrade_password_storage(data_dir)
    return state


def upgrade_password_storage(data_dir: Path) -> None:
    """Hash leftover plaintext user passwords in snapshots and Apply backups.

    data.json is upgraded by load_state. Router secrets are not touched.
    """
    data_dir = Path(data_dir)
    snap_dir = data_dir / "snapshots"
    if snap_dir.is_dir():
        for path in snap_dir.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            users = payload.get("users") if isinstance(payload, dict) else None
            if not isinstance(users, list) or not migrate_users(users):
                continue
            _write_private_json(path, payload)
    backup_root = data_dir / "backups"
    if not backup_root.is_dir():
        return
    for path in backup_root.glob("*/users"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        updated = rewrite_cleartext_passwords(text)
        if updated == text:
            continue
        path.write_text(updated, encoding="utf-8")


def _write_private_json(path: Path, payload: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)


def set_admin_password(state: dict, password: str) -> None:
    """Store a new admin password hash and rotate the session key.

    Rotating the key makes cookies signed with the old key stop working.
    The plaintext password is not stored.
    """
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    state["admin_password_hash"] = hash_password(password)
    state["initial_password_shown"] = True
    state["secret_key"] = secrets.token_hex(32)


def check_admin_password(state: dict, username: str, password: str) -> bool:
    stored = state.get("admin_password_hash") or ""
    user_ok = hmac.compare_digest(username.encode("utf-8"), ADMIN_USERNAME.encode("utf-8"))
    if not stored:
        return False
    pass_ok = verify_password(password, stored)
    return user_ok and pass_ok
