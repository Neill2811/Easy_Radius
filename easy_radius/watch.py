"""Router health, login bursts, and notifications."""

from __future__ import annotations

import json
import smtplib
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from email.message import EmailMessage

from easy_radius.automation import automation_key, decrypt_secret, encrypt_secret


def login_bursts(events: list[dict], now: int, minutes: int, threshold: int) -> list[dict]:
    cutoff = now - max(1, minutes) * 60
    counts: Counter[str] = Counter()
    for event in events:
        if event.get("result") != "Access-Reject":
            continue
        if int(event.get("time") or 0) < cutoff:
            continue
        user = str(event.get("user") or "(unknown)")
        counts[user] += 1
    return [{"user": user, "count": count} for user, count in counts.items() if count >= threshold]


def resource_alerts(readings: list[dict], cpu_limit: int, memory_limit: int) -> list[dict]:
    found = []
    for reading in readings:
        cpu = _number(reading.get("cpu"))
        memory = _number(reading.get("memory_used_pct"))
        if cpu is not None and cpu >= cpu_limit:
            found.append({"kind": "cpu", "router_id": reading.get("id"), "site_name": reading.get("site_name"), "detail": f"CPU {cpu}%"})
        if memory is not None and memory >= memory_limit:
            found.append({"kind": "memory", "router_id": reading.get("id"), "site_name": reading.get("site_name"), "detail": f"Memory {memory}%"})
    return found


def down_alerts(health_rows: list[dict], names: dict[str, str]) -> list[dict]:
    found = []
    for row in health_rows:
        if row.get("age") is None or row.get("up"):
            continue
        router_id = str(row.get("id") or "")
        found.append({"kind": "down", "router_id": router_id, "site_name": names.get(router_id, router_id), "detail": "No recent RADIUS packet"})
    return found


def alert_key(alert: dict) -> str:
    return "|".join([str(alert.get("kind")), str(alert.get("router_id") or ""), str(alert.get("user") or ""), str(alert.get("detail") or "")])


def deliver(settings: dict, state: dict, message: str, smtp_send=None, http_post=None) -> None:
    key = automation_key(state)
    if settings.get("smtp_host") and settings.get("smtp_to"):
        password = ""
        if settings.get("smtp_password_enc"):
            password = decrypt_secret(key, settings["smtp_password_enc"])
        sender = smtp_send or _smtp_send
        sender(
            host=str(settings.get("smtp_host")),
            port=int(settings.get("smtp_port") or 587),
            username=str(settings.get("smtp_user") or ""),
            password=password,
            sender=str(settings.get("smtp_from") or settings.get("smtp_user") or ""),
            recipient=str(settings.get("smtp_to")),
            use_tls=bool(settings.get("smtp_tls", True)),
            body=message,
        )
    if settings.get("telegram_chat") and settings.get("telegram_token_enc"):
        token = decrypt_secret(key, settings["telegram_token_enc"])
        poster = http_post or _telegram_post
        poster(token, str(settings["telegram_chat"]), message)


def _smtp_send(*, host, port, username, password, sender, recipient, use_tls, body) -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = "Easy Radius alert"
    message.set_content(body)
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if use_tls:
            smtp.starttls()
        if username:
            smtp.login(username, password)
        smtp.send_message(message)


def _telegram_post(token: str, chat: str, text: str) -> None:
    payload = json.dumps({"chat_id": chat, "text": text}).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        response.read()


def save_channel_secret(state: dict, settings: dict, field: str, plaintext: str) -> None:
    if not plaintext:
        return
    settings[field] = encrypt_secret(automation_key(state), plaintext)


def _number(value) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
