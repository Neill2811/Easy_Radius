"""Passphrase-encrypted export of the Easy Radius data file."""

from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from easy_radius.userhash import migrate_users

MAGIC = b"EASYRADIUS1"
KDF_ITERATIONS = 200_000


class BackupError(Exception):
    pass


def export_payload(state: dict) -> dict:
    users = deepcopy(state.get("users") or [])
    migrate_users(users)
    return {
        "version": 1,
        "routers": state.get("routers") or [],
        "users": users,
        "localhost_secret": state.get("localhost_secret") or "",
        "radius_server_address": state.get("radius_server_address") or "",
        "audit": state.get("audit") or [],
        "totp_secret": state.get("totp_secret") or "",
        "totp_enabled": bool(state.get("totp_enabled")),
        "admin_password_hash": state.get("admin_password_hash") or "",
    }


def apply_payload(state: dict, payload: dict) -> None:
    if payload.get("version") != 1:
        raise BackupError("This file is not an Easy Radius backup.")
    if not isinstance(payload.get("routers"), list) or not isinstance(payload.get("users"), list):
        raise BackupError("This backup is incomplete.")
    users = payload["users"]
    migrate_users(users)
    state["routers"] = payload["routers"]
    state["users"] = users
    if payload.get("localhost_secret"):
        state["localhost_secret"] = payload["localhost_secret"]
    state["radius_server_address"] = payload.get("radius_server_address") or ""
    state["audit"] = list(payload.get("audit") or [])
    state["totp_secret"] = payload.get("totp_secret") or ""
    state["totp_pending_secret"] = ""
    state["totp_enabled"] = bool(payload.get("totp_enabled"))
    if payload.get("admin_password_hash"):
        state["admin_password_hash"] = payload["admin_password_hash"]


def encrypt_backup(payload: dict, passphrase: str, iterations: int = KDF_ITERATIONS) -> bytes:
    if len(passphrase) < 8:
        raise BackupError("Use a passphrase of at least 8 characters.")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=32)
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    token = AESGCM(key).encrypt(nonce, body, MAGIC)
    return MAGIC + salt + nonce + iterations.to_bytes(4, "big") + token


def decrypt_backup(blob: bytes, passphrase: str) -> dict:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 16 + 12 + 4 + 16:
        raise BackupError("This file is not an Easy Radius backup.")
    offset = len(MAGIC)
    salt = blob[offset : offset + 16]
    offset += 16
    nonce = blob[offset : offset + 12]
    offset += 12
    iterations = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    if iterations < 1 or iterations > 2_000_000:
        raise BackupError("This backup could not be read.")
    token = blob[offset:]
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=32)
    try:
        body = AESGCM(key).decrypt(nonce, token, MAGIC)
    except Exception as exc:
        raise BackupError("Passphrase is not correct, or the file is damaged.") from exc
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("This backup could not be read.") from exc
    if not isinstance(payload, dict):
        raise BackupError("This backup could not be read.")
    return payload
