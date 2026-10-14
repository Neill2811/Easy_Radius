"""Monitoring, temporary access, and PDF reports."""

from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Response, flash, redirect, render_template, request, url_for

from easy_radius.access import drop_expired_grants
from easy_radius.apply import apply_configuration
from easy_radius.audit import record
from easy_radius.automation import AutomationError, account_password
from easy_radius.logs import packet_times, parse_auth_log, router_health, tail_text
from easy_radius.reports import build_report
from easy_radius.store import load_state, save_state
from easy_radius.watch import (
    alert_key,
    deliver,
    down_alerts,
    login_bursts,
    resource_alerts,
    save_channel_secret,
)

_STARTED = False


def register_watch(app) -> None:
    if not app.config.get("TESTING"):
        _start(app)

    @app.get("/monitoring")
    def monitoring():
        state = load_state(app.config["DATA_DIR"])
        settings = _settings(state)
        return render_template(
            "monitoring.html",
            settings=settings,
            alerts=state.get("monitor_alerts") or [],
            smtp_saved=bool(settings.get("smtp_password_enc")),
            telegram_saved=bool(settings.get("telegram_token_enc")),
        )

    @app.post("/monitoring/settings")
    def monitoring_settings():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        settings = _settings(state)
        settings["enabled"] = request.form.get("enabled") == "yes"
        settings["smtp_host"] = request.form.get("smtp_host", "").strip()
        settings["smtp_port"] = request.form.get("smtp_port", "587").strip() or "587"
        settings["smtp_user"] = request.form.get("smtp_user", "").strip()
        settings["smtp_from"] = request.form.get("smtp_from", "").strip()
        settings["smtp_to"] = request.form.get("smtp_to", "").strip()
        settings["smtp_tls"] = request.form.get("smtp_tls") == "yes"
        settings["telegram_chat"] = request.form.get("telegram_chat", "").strip()
        try:
            settings["cpu_pct"] = max(1, min(100, int(request.form.get("cpu_pct", "90"))))
            settings["memory_pct"] = max(1, min(100, int(request.form.get("memory_pct", "90"))))
            settings["reject_count"] = max(1, min(1000, int(request.form.get("reject_count", "10"))))
            settings["interval_minutes"] = max(1, min(1440, int(request.form.get("interval_minutes", "15"))))
        except ValueError:
            flash("Thresholds must be numbers.", "error")
            return redirect(url_for("monitoring"))
        save_channel_secret(state, settings, "smtp_password_enc", request.form.get("smtp_password", ""))
        save_channel_secret(state, settings, "telegram_token_enc", request.form.get("telegram_token", ""))
        state["monitor_settings"] = settings
        record(state, "monitoring", "Updated alert settings")
        save_state(data_dir, state)
        flash("Alert settings saved. Passwords and the Telegram token are not shown again.", "ok")
        return redirect(url_for("monitoring"))

    @app.post("/monitoring/check")
    def monitoring_check():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        _check_monitors(app, state)
        save_state(data_dir, state)
        flash("Monitoring check finished.", "ok")
        return redirect(url_for("monitoring"))

    @app.get("/grants")
    def grants():
        state = load_state(app.config["DATA_DIR"])
        tags = []
        for router in state["routers"]:
            for tag in router.get("tags") or []:
                if tag not in tags:
                    tags.append(tag)
        return render_template(
            "grants.html",
            users=[user for user in state["users"] if user.get("enabled", True)],
            routers=[router for router in state["routers"] if router.get("enabled", True)],
            tags=tags,
            grants=state.get("grants") or [],
        )

    @app.post("/grants")
    def grants_create():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        user = next((item for item in state["users"] if item["id"] == request.form.get("user_id")), None)
        if user is None:
            flash("Choose a user.", "error")
            return redirect(url_for("grants"))
        try:
            hours = max(1, min(168, int(request.form.get("hours", "8"))))
        except ValueError:
            flash("Duration must be a number of hours.", "error")
            return redirect(url_for("grants"))
        router_ids = [router_id for router_id in request.form.getlist("router_ids") if any(router["id"] == router_id for router in state["routers"])]
        known_tags = {tag for router in state["routers"] for tag in (router.get("tags") or [])}
        tags = [tag for tag in request.form.getlist("tags") if tag in known_tags]
        if not router_ids and not tags:
            flash("Choose a router or a site group.", "error")
            return redirect(url_for("grants"))
        if len(router_ids) + len(tags) > 1 and request.form.get("confirm_many") != "yes":
            flash("Confirm the grant. It covers more than one router or group.", "error")
            return redirect(url_for("grants"))
        expires = datetime.now(timezone.utc) + timedelta(hours=hours)
        grant = {
            "id": secrets.token_hex(8),
            "user_id": user["id"],
            "username": user["username"],
            "router_ids": router_ids,
            "tags": tags,
            "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": "neill",
        }
        state.setdefault("grants", []).append(grant)
        record(state, "access.grant", f"Granted {user['username']} temporary access until {grant['expires_at']}")
        _reapply(app, state)
        save_state(data_dir, state)
        flash("Temporary access saved and FreeRADIUS was updated.", "ok")
        return redirect(url_for("grants"))

    @app.get("/reports")
    def reports():
        return render_template("reports.html")

    @app.post("/reports/download")
    def reports_download():
        state = load_state(app.config["DATA_DIR"])
        month = request.form.get("month", "").strip() or datetime.now(timezone.utc).strftime("%Y-%m")
        pdf = build_report(state, tail_text(Path(app.config["AUTH_LOG"])))
        if request.form.get("email") == "yes":
            settings = _settings(state)
            try:
                from easy_radius.watch import deliver

                deliver(settings, state, f"Easy Radius report {month} is attached in the download. This message is the notice.")
            except Exception as exc:
                flash(f"Report built, but email failed: {exc}", "error")
        record(state, "report", f"Downloaded the {month} report")
        save_state(app.config["DATA_DIR"], state)
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=easy-radius-{month}.pdf"},
        )


def _settings(state: dict) -> dict:
    defaults = {
        "enabled": True,
        "interval_minutes": 15,
        "cpu_pct": 90,
        "memory_pct": 90,
        "reject_count": 10,
        "reject_minutes": 10,
        "smtp_host": "",
        "smtp_port": "587",
        "smtp_user": "",
        "smtp_password_enc": "",
        "smtp_from": "",
        "smtp_to": "",
        "smtp_tls": True,
        "telegram_token_enc": "",
        "telegram_chat": "",
        "last_check": "",
        "seen_alerts": [],
    }
    defaults.update(state.get("monitor_settings") or {})
    return defaults


def _check_monitors(app, state: dict) -> None:
    settings = _settings(state)
    now = int(time.time())
    auth = parse_auth_log(tail_text(Path(app.config["AUTH_LOG"])))
    names = {router["id"]: router["site_name"] for router in state["routers"]}
    health = router_health(state["routers"], packet_times(auth, []), now, int(app.config.get("HEALTH_SECONDS") or 900))
    alerts = down_alerts(health, names)
    for burst in login_bursts(auth, now, int(settings["reject_minutes"]), int(settings["reject_count"])):
        alerts.append({"kind": "brute", "router_id": "", "user": burst["user"], "site_name": "", "detail": f"{burst['count']} failed logins for {burst['user']}"})
    readings = _resource_readings(app, state)
    alerts.extend(resource_alerts(readings, int(settings["cpu_pct"]), int(settings["memory_pct"])))
    seen = set(settings.get("seen_alerts") or [])
    fresh = [alert for alert in alerts if alert_key(alert) not in seen]
    settings["seen_alerts"] = [alert_key(alert) for alert in alerts][-200:]
    settings["last_check"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    state["monitor_settings"] = settings
    state["monitor_alerts"] = alerts[:100]
    if fresh and settings.get("enabled", True):
        message = "Easy Radius\n" + "\n".join(alert["detail"] for alert in fresh)
        try:
            deliver(settings, state, message)
        except Exception as exc:
            record(state, "monitoring", f"Alert delivery failed: {exc}")
        else:
            record(state, "monitoring", "Sent alerts: " + "; ".join(alert["detail"] for alert in fresh))


def _resource_readings(app, state: dict) -> list[dict]:
    try:
        username, password = account_password(state)
    except AutomationError:
        return []
    connector = app.config.get("ROUTER_CONNECT")
    if connector is None:
        from easy_radius.routeros_api import connect_router

        connector = connect_router
    readings = []
    for router in state["routers"]:
        if router.get("enabled", True) is False:
            continue
        session = None
        try:
            allow = bool(router.get("api_plaintext"))
            try:
                session = connector(router["ip"], username, password, allow_plaintext=allow)
            except TypeError:
                session = connector(router["ip"], username, password)
            resource = session.get("/system/resource")
        except Exception:
            continue
        finally:
            if session is not None and getattr(session, "close", None):
                try:
                    session.close()
                except Exception:
                    pass
        total = _int(resource.get("total-memory"))
        free = _int(resource.get("free-memory"))
        memory = ""
        if total and free is not None and total > 0:
            memory = str(round((total - free) * 100 / total))
        readings.append({"id": router["id"], "site_name": router["site_name"], "cpu": resource.get("cpu-load"), "memory_used_pct": memory})
    return readings


def _int(value):
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _reapply(app, state: dict) -> None:
    apply_configuration(
        state,
        app.config["RUNNER"],
        app.config["CLIENTS_CONF"],
        app.config["USERS_FILE"],
        Path(app.config["DATA_DIR"]) / "backups",
        app.config["POLICY_FILE"],
    )


def _expire(app) -> None:
    with app.app_context():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        expired = drop_expired_grants(state)
        if not expired:
            return
        for grant in expired:
            record(state, "access.expire", f"Temporary access for {grant.get('username')} expired")
        _reapply(app, state)
        save_state(data_dir, state)


def _start(app) -> None:
    global _STARTED
    if _STARTED:
        return
    _STARTED = True

    def loop() -> None:
        while True:
            time.sleep(60)
            try:
                _expire(app)
            except Exception:
                pass
            try:
                with app.app_context():
                    state = load_state(app.config["DATA_DIR"])
                    settings = _settings(state)
                    if not settings.get("enabled", True):
                        continue
                    last = str(settings.get("last_check") or "")
                    due = True
                    if last:
                        previous = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                        due = datetime.now(timezone.utc) - previous >= timedelta(minutes=int(settings.get("interval_minutes") or 15))
                    if due:
                        _check_monitors(app, state)
                        save_state(app.config["DATA_DIR"], state)
                    _maybe_monthly(app, state)
            except Exception:
                continue

    threading.Thread(target=loop, name="easy-radius-watch", daemon=True).start()


def _maybe_monthly(app, state: dict) -> None:
    now = datetime.now(timezone.utc)
    if now.day != 1 or now.hour < 6:
        return
    period = now.strftime("%Y-%m")
    if str(state.get("last_report_month") or "") == period:
        return
    state["last_report_month"] = period
    settings = _settings(state)
    if settings.get("smtp_to"):
        try:
            from easy_radius.watch import deliver

            deliver(settings, state, f"Easy Radius monthly report {period} is ready to download.")
        except Exception:
            pass
    record(state, "report", f"Monthly report {period} is ready")
    save_state(app.config["DATA_DIR"], state)
