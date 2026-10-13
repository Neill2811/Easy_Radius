"""Decide whether a firewall change would lock out the current SSH client."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys


def parse_subnets(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    if raw is None:
        return []
    parts = [part for part in re.split(r"[\s,]+", raw.strip()) if part]
    networks = []
    for part in parts:
        networks.append(ipaddress.ip_network(part, strict=False))
    return networks


def ssh_client_allowed(client_ip: str, admin_subnets: str) -> bool:
    if not client_ip:
        return False
    ip = ipaddress.ip_address(client_ip.strip())
    return any(ip in network for network in parse_subnets(admin_subnets))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check that an SSH client is inside the admin subnets.")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--subnets", required=True)
    args = parser.parse_args(argv)
    try:
        allowed = ssh_client_allowed(args.ip, args.subnets)
    except ValueError as exc:
        print(f"Invalid IP or subnet: {exc}", file=sys.stderr)
        return 2
    if allowed:
        print("allowed")
        return 0
    print("denied")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
