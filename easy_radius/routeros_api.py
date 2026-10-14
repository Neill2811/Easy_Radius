"""RouterOS API session.

API-SSL on port 8729 is always tried first. The plaintext API on port
8728 is used only when that router has opted in. MikroTik's default
API-SSL certificate is self-signed, so the TLS check does not require a
public certificate authority. The service account password is not
included in errors.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass

from easy_radius.automation import AutomationError


SSL_PORT = 8729
PLAIN_PORT = 8728


def _ssl_wrapper():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket


def _scrub(text: str, password: str) -> str:
    if password and password in text:
        return text.replace(password, "<password>")
    return text


@dataclass
class ApiSession:
    api: object
    port: int

    def rows(self, path: str) -> list[dict]:
        parts = [part for part in path.strip("/").split("/") if part]
        return [dict(row) for row in self.api.path(*parts)]

    def get(self, path: str) -> dict[str, str]:
        found = self.rows(path)
        if not found:
            return {}
        row = dict(found[0])
        row.pop(".id", None)
        return {str(key): _stringify(value) for key, value in row.items()}

    def set(self, path: str, values: dict[str, str]) -> None:
        self.set_matching(path, {}, values)

    def set_matching(self, path: str, where: dict[str, str], values: dict[str, str]) -> None:
        parts = [part for part in path.strip("/").split("/") if part]
        node = self.api.path(*parts)
        found = list(node)
        matched = found if not where else [row for row in found if _matches(row, where)]
        if where and not matched:
            raise AutomationError(f"No row on {path} matched {where}")
        if not matched:
            node.update(**values)
            return
        for row in matched:
            payload = dict(values)
            if row.get(".id"):
                payload[".id"] = row[".id"]
            node.update(**payload)

    def export(self) -> str:
        # show-sensitive stays off so the saved export does not keep router secrets.
        return self.api.config().export(show_sensitive=False)

    def restore(self, text: str) -> None:
        self.api.config().apply(text)

    def close(self) -> None:
        self.api.close()


def _stringify(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _matches(row: dict, where: dict[str, str]) -> bool:
    for key, expected in where.items():
        if str(row.get(key, "")).strip().lower() != str(expected).strip().lower():
            return False
    return True


def connect_router(
    host: str,
    username: str,
    password: str,
    timeout: float = 15,
    allow_plaintext: bool = False,
) -> ApiSession:
    from librouteros import connect

    errors: list[str] = []
    try:
        api = connect(
            host=host,
            username=username,
            password=password,
            port=SSL_PORT,
            timeout=timeout,
            ssl_wrapper=_ssl_wrapper(),
        )
        return ApiSession(api=api, port=SSL_PORT)
    except Exception as exc:
        errors.append(f"API-SSL port {SSL_PORT}: {_scrub(str(exc), password)}")
    if not allow_plaintext:
        raise AutomationError("Could not open API-SSL on port 8729. " + " ".join(errors))
    try:
        api = connect(
            host=host,
            username=username,
            password=password,
            port=PLAIN_PORT,
            timeout=timeout,
        )
        return ApiSession(api=api, port=PLAIN_PORT)
    except Exception as exc:
        errors.append(f"API port {PLAIN_PORT}: {_scrub(str(exc), password)}")
    raise AutomationError("Could not open the RouterOS API. " + " ".join(errors))
