"""Input checks for routers and users."""

from __future__ import annotations

import ipaddress
import re

from easy_radius.configgen import GROUPS

_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}$")
_SITE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")


def valid_secret(value: str) -> bool:
    if not value or len(value) > 128:
        return False
    return all(32 <= ord(char) < 127 for char in value)


def validate_router(site_name: str, ip_text: str, secret: str, routers: list[dict], current_id: str | None = None) -> str | None:
    site_name = site_name.strip()
    ip_text = ip_text.strip()
    if not _SITE.fullmatch(site_name):
        return "Site name can use letters, numbers, spaces, and . _ -"
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "Enter a valid IPv4 or IPv6 address"
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "That address cannot be used for a site router"
    if not valid_secret(secret):
        return "Secret must be 1-128 printable ASCII characters"
    for router in routers:
        if current_id and router["id"] == current_id:
            continue
        if router["ip"] == str(ip):
            return "A router with that IP already exists"
    return None


def canonical_ip(ip_text: str) -> str:
    return ipaddress.ip_address(ip_text.strip()).compressed


def validate_user(username: str, password: str, group: str, users: list[dict], current_id: str | None = None) -> str | None:
    username = username.strip()
    if not _USERNAME.fullmatch(username):
        return "Username can use letters, numbers, and . _ @ + -"
    if not valid_secret(password):
        return "Password must be 1-128 printable ASCII characters"
    if group not in GROUPS:
        return "Choose full, write, or read"
    for user in users:
        if current_id and user["id"] == current_id:
            continue
        if user["username"].lower() == username.lower():
            return "That username already exists"
    return None
