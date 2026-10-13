"""RouterOS commands for one site router."""

from __future__ import annotations

import re


def _ros_word(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9._@+-]+", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def mikrotik_commands(server: str, secret: str, router_ip: str) -> str:
    """RouterOS lines that send RADIUS from the router's own address.

    The first line adds this server. The second updates an entry that is
    already there. src-address is the router IP stored in Easy Radius.
    """
    hidden = _ros_word(secret)
    server_word = _ros_word(server)
    router_word = _ros_word(router_ip)
    return (
        f"/radius add address={server_word} secret={hidden} service=login "
        f"src-address={router_word} timeout=3s\n"
        f"/radius set [find address={server_word}] src-address={router_word} secret={hidden}\n"
        "/user aaa set use-radius=yes\n"
    )
