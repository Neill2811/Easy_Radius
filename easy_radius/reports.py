"""On-demand and monthly PDF reports of logins and changes."""

from __future__ import annotations

from datetime import datetime, timezone

from easy_radius.logs import parse_auth_log
from easy_radius.pdftext import text_pdf


def build_report(state: dict, auth_text: str, when: datetime | None = None, month: str | None = None) -> bytes:
    moment = when or datetime.now(timezone.utc)
    period = month or moment.strftime("%Y-%m")
    lines = [
        "Easy Radius report",
        f"Period {period}",
        f"Generated {moment.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "Changes",
    ]
    changes = [
        event
        for event in state.get("audit") or []
        if str(event.get("at") or "").startswith(period)
    ]
    if not changes:
        lines.append("No changes in this period.")
    for event in changes:
        lines.append(f"{event.get('at')} {event.get('actor')} {event.get('detail')}")
    lines.append("")
    lines.append("Logins")
    logins = []
    for event in parse_auth_log(auth_text):
        stamp = datetime.fromtimestamp(int(event["time"]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if not stamp.startswith(period):
            continue
        logins.append(f"{stamp} {event.get('result')} {event.get('user')} {event.get('nas')}")
    if not logins:
        lines.append("No login lines in this period.")
    lines.extend(logins[:500])
    return text_pdf(lines)
