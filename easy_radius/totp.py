"""Time-based one-time passwords for the admin login (RFC 6238, SHA-1)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def generate_secret() -> str:
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    padded = secret.strip().upper().replace(" ", "")
    padded += "=" * ((8 - len(padded) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def totp_at(secret: str, when: int, step: int = 30, digits: int = 6) -> str:
    key = _decode_secret(secret)
    counter = int(when // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify_totp(secret: str, code: str, now: int | None = None, window: int = 1) -> bool:
    cleaned = "".join(ch for ch in code if ch.isdigit())
    if len(cleaned) != 6 or not secret:
        return False
    moment = int(time.time() if now is None else now)
    for offset in range(-window, window + 1):
        expected = totp_at(secret, moment + offset * 30)
        if hmac.compare_digest(expected, cleaned):
            return True
    return False


def provisioning_uri(secret: str, username: str = "neill") -> str:
    label = quote(f"Easy Radius:{username}")
    issuer = quote("Easy Radius")
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&digits=6&period=30"
