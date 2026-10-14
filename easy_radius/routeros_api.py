"""RouterOS API session.

API-SSL on port 8729 is tried first. If that port does not answer, the
plaintext API on port 8728 is used. MikroTik's default API-SSL certificate
is self-signed, so the TLS check does not require a public certificate
authority. The service account password is not included in errors.
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

    def get(self, path: str) -> dict[str, str]:
        parts = [part for part in path.strip("/").split("/") if part]
        rows = list(self.api.path(*parts))
        if not rows:
            return {}
        row = dict(rows[0])
        row.pop(".id", None)
        return {str(key): _stringify(value) for key, value in row.items()}

    def set(self, path: str, values: dict[str, str]) -> None:
        parts = [part for part in path.strip("/").split("/") if part]
        node = self.api.path(*parts)
        rows = list(node)
        payload = dict(values)
        if rows and rows[0].get(".id"):
            payload[".id"] = rows[0][".id"]
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


def connect_router(host: str, username: str, password: str, timeout: float = 15) -> ApiSession:
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
