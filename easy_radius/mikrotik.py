"""RouterOS commands for one site router."""

from __future__ import annotations

import re


def _ros_secret(secret: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9._@+-]+", secret):
        return secret
    escaped = secret.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def mikrotik_commands(server: str, secret: str) -> str:
    return (
        f"/radius add address={server} secret={_ros_secret(secret)} service=login\n"
        "/user aaa set use-radius=yes\n"
    )
