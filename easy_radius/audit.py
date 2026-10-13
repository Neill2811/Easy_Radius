"""Append-only record of admin changes."""

from __future__ import annotations

from datetime import datetime, timezone

MAX_EVENTS = 500


def record(state: dict, action: str, detail: str, actor: str = "neill") -> None:
    events = list(state.get("audit") or [])
    events.append(
        {
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": actor,
            "action": action,
            "detail": detail,
        }
    )
    state["audit"] = events[-MAX_EVENTS:]
