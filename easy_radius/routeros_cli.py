"""Plain RouterOS CLI lines, turned into the same steps a YAML task uses.

One command per line. A line starts with a path, then a verb, then
key=value arguments and an optional item name or ``[find ...]``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_VERBS = {"set", "add", "remove", "enable", "disable"}
_PATH = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9_/-]*$")
_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_MAX_BODY = 64 * 1024

# Paths and attributes Easy Radius knows. Anything else is a warning, not an error.
KNOWN: dict[str, set[str]] = {
    "/ip/dns": {"servers", "allow-remote-requests"},
    "/system/ntp/client": {"enabled", "servers"},
    "/system/identity": {"name"},
    "/ip/service": {"name", "address", "disabled", "port"},
    "/user": {"name", "group", "password", "disabled", "comment"},
    "/user/aaa": {"use-radius"},
    "/snmp": {"enabled", "contact", "location"},
    "/ip/firewall/filter": {
        "chain",
        "action",
        "protocol",
        "src-address",
        "dst-address",
        "dst-port",
        "comment",
        "disabled",
        "connection-state",
    },
    "/ip/firewall/nat": {
        "chain",
        "action",
        "protocol",
        "src-address",
        "dst-address",
        "to-addresses",
        "to-ports",
        "comment",
        "disabled",
    },
    "/ip/address": {"address", "interface", "comment", "disabled"},
    "/ip/route": {"dst-address", "gateway", "comment", "disabled", "distance"},
    "/system/clock": {"time-zone-name"},
    "/interface": {"name", "disabled", "comment"},
}


class CommandSyntaxError(Exception):
    """One line failed the syntax check. The message has no line number."""


@dataclass
class Command:
    path: str
    verb: str
    values: dict[str, str] = field(default_factory=dict)
    where: dict[str, str] = field(default_factory=dict)


def looks_like_commands(body: str) -> bool:
    lines = []
    for raw in body.splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return bool(lines) and all(line.startswith("/") for line in lines)


def parse_commands(body: str) -> tuple[list[Command], list[str]]:
    """Parse CLI lines. Syntax problems raise CommandSyntaxError's parent via SyntaxError list.

    Returns the commands and warnings for unknown paths or attributes.
    A syntax error lists every bad line and does not return commands.
    """
    if len(body.encode("utf-8")) > _MAX_BODY:
        raise CommandSyntaxError("That task is too large.")
    commands: list[Command] = []
    warnings: list[str] = []
    errors: list[str] = []
    for number, raw in enumerate(body.splitlines(), start=1):
        text = _strip_comment(raw).strip()
        if not text:
            continue
        try:
            command, line_warnings = _parse_line(text)
        except CommandSyntaxError as exc:
            errors.append(f"Line {number}: {exc}")
            continue
        commands.append(command)
        warnings.extend(f"Line {number}: {warning}" for warning in line_warnings)
    if errors:
        raise CommandSyntaxError("\n".join(errors))
    if not commands or len(commands) > 100:
        raise CommandSyntaxError("A task needs between 1 and 100 commands.")
    return commands, warnings


def _parse_line(text: str) -> tuple[Command, list[str]]:
    tokens = _tokenize(text)
    if not tokens or not tokens[0].startswith("/"):
        raise CommandSyntaxError("expected a command starting with /")
    path_parts = [part for part in tokens[0].split("/") if part]
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in _VERBS or token.startswith("[") or "=" in token:
            break
        path_parts.append(token)
        index += 1
    if not path_parts:
        raise CommandSyntaxError("expected a path")
    path = "/" + "/".join(path_parts)
    if not _PATH.fullmatch(path):
        raise CommandSyntaxError(f"unsupported path {path}")
    if index >= len(tokens) or tokens[index] not in _VERBS:
        raise CommandSyntaxError("expected a verb (set, add, remove, enable, disable)")
    verb = tokens[index]
    index += 1
    where: dict[str, str] = {}
    values: dict[str, str] = {}
    saw_selector = False
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token.startswith("[") and token.endswith("]"):
            if saw_selector:
                raise CommandSyntaxError("only one selector is allowed")
            where.update(_parse_find(token))
            saw_selector = True
            continue
        if token == "where":
            raise CommandSyntaxError("put where inside [find where name=value]")
        if "=" in token:
            key, value = _pair(token)
            if key in values:
                raise CommandSyntaxError(f"duplicate attribute {key}")
            values[key] = value
            continue
        if saw_selector:
            raise CommandSyntaxError(f"unexpected {token}")
        if not _NAME.fullmatch(token):
            raise CommandSyntaxError("use [find ...] instead of an item number")
        where["name"] = token
        saw_selector = True
    if verb == "set" and not values:
        raise CommandSyntaxError("set needs at least one name=value")
    if verb == "add":
        if saw_selector:
            raise CommandSyntaxError("add does not take a selector")
        if not values:
            raise CommandSyntaxError("add needs at least one name=value")
    if verb in {"remove", "enable", "disable"} and not where:
        raise CommandSyntaxError(f"{verb} needs an item name or [find ...]")
    if verb == "remove" and values:
        raise CommandSyntaxError("remove takes a selector, not name=value")
    return Command(path=path, verb=verb, values=values, where=where), _warnings(path, values, where)


def _warnings(path: str, values: dict[str, str], where: dict[str, str]) -> list[str]:
    known = KNOWN.get(path)
    if known is None:
        return [f"unknown path {path}"]
    found = []
    for key in list(values) + list(where):
        if key not in known:
            found.append(f"unknown attribute {key} on {path}")
    return found


def _parse_find(token: str) -> dict[str, str]:
    inner = token[1:-1].strip()
    parts = _tokenize(inner)
    if not parts or parts[0] != "find":
        raise CommandSyntaxError("a selector must look like [find name=value]")
    rest = parts[1:]
    if rest and rest[0] == "where":
        rest = rest[1:]
    if not rest:
        raise CommandSyntaxError("find needs a condition")
    where: dict[str, str] = {}
    for item in rest:
        if "=" not in item:
            raise CommandSyntaxError("find conditions must be name=value")
        key, value = _pair(item)
        if key in where:
            raise CommandSyntaxError(f"duplicate condition {key}")
        where[key] = value
    return where


def _pair(token: str) -> tuple[str, str]:
    key, _, value = token.partition("=")
    key = key.strip()
    if not _KEY.fullmatch(key):
        raise CommandSyntaxError(f"unsupported attribute {key or token}")
    return key, _unquote(value.strip())


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    return value


def _strip_comment(line: str) -> str:
    in_quote = False
    index = 0
    while index < len(line):
        if line[index] == '"':
            in_quote = not in_quote
        elif line[index] == "#" and not in_quote:
            return line[:index]
        index += 1
    return line


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    buf: list[str] = []
    in_quote = False
    depth = 0
    index = 0
    while index < len(text):
        if in_quote:
            char = text[index]
            buf.append(char)
            if char == "\\" and index + 1 < len(text):
                buf.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_quote = False
            index += 1
            continue
        if depth == 0 and text.startswith("{{", index):
            end = text.find("}}", index)
            if end < 0:
                raise CommandSyntaxError("a variable placeholder was not closed")
            buf.append(text[index : end + 2])
            index = end + 2
            continue
        char = text[index]
        if char == '"':
            in_quote = True
            buf.append(char)
            index += 1
            continue
        if char == "[":
            depth += 1
            buf.append(char)
            index += 1
            continue
        if char == "]":
            if depth == 0:
                raise CommandSyntaxError("a closing bracket has no match")
            depth -= 1
            buf.append(char)
            index += 1
            continue
        if char.isspace() and depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    if in_quote:
        raise CommandSyntaxError("a quoted value was not closed")
    if depth:
        raise CommandSyntaxError("brackets were not closed")
    if buf:
        tokens.append("".join(buf))
    return tokens
