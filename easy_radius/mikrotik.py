"""RouterOS commands for one site router."""

from __future__ import annotations

import re


def _ros_word(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9._@+-]+", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _host_cidr(address: str) -> str:
    """One host, as RouterOS writes an address list entry."""
    prefix = "128" if ":" in address else "32"
    literal = f"{address}/{prefix}"
    if re.fullmatch(r"[0-9.]+/32", literal):
        return literal
    return _ros_word(literal)


def mikrotik_commands(server: str, secret: str, router_ip: str) -> str:
    """RouterOS lines that send RADIUS from the router's own address.

    The first line adds this server. The second updates an entry that is
    already there. src-address is the router IP stored in Easy Radius.
    The later lines create an API-SSL certificate for that same router IP
    and allow only this server on port 8729. Each condition is one line, so
    a RouterOS terminal does not join '}' with the next command. A signed
    api-ssl certificate is left alone. One that exists but was not signed
    by api-ssl-ca is removed and created again.
    """
    hidden = _ros_word(secret)
    server_word = _ros_word(server)
    router_word = _ros_word(router_ip)
    server_cidr = _host_cidr(server)
    return (
        f"/radius add address={server_word} secret={hidden} service=login "
        f"src-address={router_word} timeout=3s\n"
        f"/radius set [find address={server_word}] src-address={router_word} secret={hidden}\n"
        "/user aaa set use-radius=yes\n"
        ":if ([:len [/certificate find name=api-ssl-ca]] = 0) do={"
        "/certificate add name=api-ssl-ca common-name=api-ssl-ca "
        "key-usage=key-cert-sign,crl-sign days-valid=3650; "
        "/certificate sign api-ssl-ca; :delay 5}\n"
        ":if ([:len [/certificate find name=api-ssl]] > 0 && "
        "[:len [/certificate find name=api-ssl ca=api-ssl-ca]] = 0) do={"
        "/certificate remove [find name=api-ssl]}\n"
        ":if ([:len [/certificate find name=api-ssl]] = 0) do={"
        f"/certificate add name=api-ssl common-name={router_word} days-valid=3650; "
        "/certificate sign api-ssl ca=api-ssl-ca; :delay 5}\n"
        f"/ip service set api-ssl certificate=api-ssl address={server_cidr} disabled=no\n"
        "# Uncomment the next line if the input chain ends with a drop rule.\n"
        "# /ip firewall filter add chain=input protocol=tcp dst-port=8729 "
        f'src-address={server_word} action=accept place-before=0 comment="Easy Radius API-SSL"\n'
    )
