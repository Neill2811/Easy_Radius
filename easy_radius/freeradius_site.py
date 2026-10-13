"""Install FreeRADIUS linelog modules for Easy Radius.

The module file is added under mods-available and enabled with a symlink.
Site files gain marked lines in accounting, post-auth, and Post-Auth-Type REJECT.
Running it again does not add a second copy.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from easy_radius.access import render_access_policy

MODULE_CONF = """# Easy Radius login and accounting logs.
# Installed by install.sh. Safe to leave in place.

linelog easy_radius_auth_accept {
\tfilename = ${logdir}/easy-radius-auth.log
\tpermissions = 0640
\tformat = "EASYRADIUS auth time=%l result=Access-Accept user=%{%{User-Name}:--} nas=%{%{Packet-Src-IP-Address}:-%{NAS-IP-Address}}"
}

linelog easy_radius_auth_reject {
\tfilename = ${logdir}/easy-radius-auth.log
\tpermissions = 0640
\tformat = "EASYRADIUS auth time=%l result=Access-Reject user=%{%{User-Name}:--} nas=%{%{Packet-Src-IP-Address}:-%{NAS-IP-Address}}"
}

linelog easy_radius_acct {
\tfilename = ${logdir}/easy-radius-acct.log
\tpermissions = 0640
\tformat = "EASYRADIUS acct time=%l status=%{%{Acct-Status-Type}:--} user=%{%{User-Name}:--} nas=%{%{Packet-Src-IP-Address}:-%{NAS-IP-Address}} session=%{%{Acct-Session-Id}:--}"
}
"""

_AUTHORIZE = re.compile(r"^(?P<indent>[ \t]*)authorize[ \t]*\{", re.M)
_ACCOUNTING = re.compile(r"^(?P<indent>[ \t]*)accounting[ \t]*\{", re.M)
_POST_AUTH = re.compile(r"^(?P<indent>[ \t]*)post-auth[ \t]*\{", re.M)
_REJECT = re.compile(r"^(?P<indent>[ \t]*)Post-Auth-Type[ \t]+REJECT[ \t]*\{", re.M)


def _block(text: str, end: int) -> str:
    depth = 1
    index = end
    while index < len(text) and depth:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    return text[end : index - 1 if depth == 0 else index]


def _has_statement(block: str, name: str) -> bool:
    return re.search(rf"(?m)^[ \t]*{re.escape(name)}[ \t]*$", block) is not None


def _insert(text: str, pattern: re.Pattern[str], marker: str, lines: list[str]) -> tuple[str, bool]:
    changed = False

    def replacer(match: re.Match[str]) -> str:
        nonlocal changed
        block = _block(text, match.end())
        if marker in block:
            return match.group(0)
        changed = True
        indent = (match.group("indent") or "") + "\t"
        extra = "".join(f"\n{indent}{line}" for line in lines)
        return match.group(0) + extra

    updated = pattern.sub(replacer, text)
    return updated, changed


def patch_site(text: str) -> tuple[str, bool]:
    updated, changed_access = _insert(
        text,
        _AUTHORIZE,
        "EASY-RADIUS-ACCESS",
        ["# EASY-RADIUS-ACCESS", "easy_radius_access"],
    )
    updated, changed_acct = _insert(
        updated,
        _ACCOUNTING,
        "EASY-RADIUS-ACCT",
        ["# EASY-RADIUS-ACCT", "easy_radius_acct"],
    )
    # Add the stock detail logger only when that accounting block does not already call it.
    if changed_acct:
        updated = _ensure_detail(updated)
    updated, changed_accept = _insert(
        updated,
        _POST_AUTH,
        "EASY-RADIUS-AUTH-ACCEPT",
        ["# EASY-RADIUS-AUTH-ACCEPT", "easy_radius_auth_accept"],
    )
    updated, changed_reject = _insert(
        updated,
        _REJECT,
        "EASY-RADIUS-AUTH-REJECT",
        ["# EASY-RADIUS-AUTH-REJECT", "easy_radius_auth_reject"],
    )
    return updated, changed_access or changed_acct or changed_accept or changed_reject


def _ensure_detail(text: str) -> str:
    def replacer(match: re.Match[str]) -> str:
        block = _block(text, match.end())
        if _has_statement(block, "detail") or "EASY-RADIUS-DETAIL" in block:
            return match.group(0)
        indent = (match.group("indent") or "") + "\t"
        return match.group(0) + f"\n{indent}# EASY-RADIUS-DETAIL\n{indent}detail"

    return _ACCOUNTING.sub(replacer, text)


def _write(path: Path, text: str) -> None:
    target = path.resolve() if path.is_symlink() else path
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f".{target.name}.easy-radius-tmp"
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, target)


def configure(freeradius_dir: Path) -> str:
    freeradius_dir = Path(freeradius_dir)
    changed = False
    available = freeradius_dir / "mods-available"
    enabled = freeradius_dir / "mods-enabled"
    module_path = available / "easy_radius"
    available.mkdir(parents=True, exist_ok=True)
    if not module_path.exists() or module_path.read_text(encoding="utf-8") != MODULE_CONF:
        _write(module_path, MODULE_CONF)
        changed = True
    link = enabled / "easy_radius"
    enabled.mkdir(parents=True, exist_ok=True)
    if not link.is_symlink():
        if link.exists():
            link.unlink()
        link.symlink_to("../mods-available/easy_radius")
        changed = True
    policy = freeradius_dir / "policy.d" / "easy_radius"
    if not policy.exists():
        policy.parent.mkdir(parents=True, exist_ok=True)
        _write(policy, render_access_policy([], []))
        changed = True
    sites = freeradius_dir / "sites-enabled"
    site_files = [path for path in sites.iterdir() if path.is_file()] if sites.is_dir() else []
    if not site_files:
        return "changed" if changed else "no-site"
    for path in sorted(site_files):
        original = path.read_text(encoding="utf-8")
        updated, site_changed = patch_site(original)
        if site_changed:
            _write(path, updated)
            changed = True
    return "changed" if changed else "unchanged"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enable Easy Radius FreeRADIUS logs.")
    parser.add_argument("--freeradius-dir", required=True)
    args = parser.parse_args(argv)
    status = configure(Path(args.freeradius_dir))
    print(status)
    return 0


if __name__ == "__main__":
    sys.exit(main())
