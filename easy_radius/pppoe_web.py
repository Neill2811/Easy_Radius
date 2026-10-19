"""PPPoE failure pages. The poll reads routers and does not change them."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from flask import abort, flash, redirect, render_template, request, url_for

from easy_radius.audit import record
from easy_radius.pppoe_failures import (
    aggregates,
    due,
    mark_removed,
    poll_routers,
    poll_status,
    settings_of,
)
from easy_radius.store import load_state, save_state

_STARTED = False


def register_pppoe(app) -> None:
    if not app.config.get("TESTING"):
        _start(app)

    @app.get("/pppoe")
    def pppoe_failures():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        chosen = request.args.get("router", "").strip()
        rows = aggregates(data_dir, state)
        if chosen:
            rows = [row for row in rows if row["router_id"] == chosen]
        return render_template(
            "pppoe.html",
            settings=settings_of(state),
            rows=rows,
            status=poll_status(data_dir, state),
            routers=state.get("routers") or [],
            chosen=chosen,
        )

    @app.post("/pppoe/settings")
    def pppoe_settings():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        settings = settings_of(state)
        settings["enabled"] = request.form.get("enabled") == "yes"
        try:
            settings["interval_minutes"] = max(1, min(1440, int(request.form.get("interval_minutes", "15"))))
            settings["threshold"] = max(1, min(100000, int(request.form.get("threshold", "10"))))
        except ValueError:
            flash("Interval and threshold must be numbers.", "error")
            return redirect(url_for("pppoe_failures"))
        state["pppoe_poll"] = settings
        record(state, "pppoe", f"PPPoE poll every {settings['interval_minutes']} minutes, alert at {settings['threshold']} failures")
        save_state(data_dir, state)
        flash("PPPoE poll settings saved.", "ok")
        return redirect(url_for("pppoe_failures"))

    @app.post("/pppoe/poll")
    def pppoe_poll():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        poll_routers(state, data_dir, _connector(app))
        record(state, "pppoe", "Polled routers for PPPoE failures")
        save_state(data_dir, state)
        flash("PPPoE poll finished.", "ok")
        return redirect(url_for("pppoe_failures"))

    @app.post("/pppoe/<router_id>/removed")
    def pppoe_removed(router_id: str):
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        if not any(str(router.get("id")) == router_id for router in state.get("routers") or []):
            abort(404)
        username = request.form.get("username", "")
        mac = request.form.get("mac", "")
        mark_removed(data_dir, router_id, username, mac)
        who = username or mac or "entry"
        record(state, "pppoe", f"Marked PPPoE failures removed for {who}")
        save_state(data_dir, state)
        flash("Hidden. It shows again only if new failures arrive.", "ok")
        return redirect(url_for("pppoe_failures"))


def _connector(app):
    connector = app.config.get("ROUTER_CONNECT")
    if connector is None:
        from easy_radius.routeros_api import connect_router

        return connect_router
    return connector


def _start(app) -> None:
    global _STARTED
    if _STARTED:
        return
    _STARTED = True

    def loop() -> None:
        while True:
            time.sleep(60)
            try:
                _maybe(app)
            except Exception:
                continue

    threading.Thread(target=loop, name="easy-radius-pppoe", daemon=True).start()


def _maybe(app) -> None:
    with app.app_context():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        now = datetime.now(timezone.utc)
        if not due(state, now):
            return
        poll_routers(state, data_dir, _connector(app), now)
        save_state(data_dir, state)
