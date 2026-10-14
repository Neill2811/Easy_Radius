"""Firmware and inventory pages."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from flask import Response, flash, redirect, render_template, request, url_for

from easy_radius.audit import record
from easy_radius.automation import AutomationError, account_password
from easy_radius.facts import (
    CHANNELS,
    fetch_latest,
    latest_by_channel,
    outdated,
    refresh_router,
    upgrade_many,
    version_label,
)
from easy_radius.store import load_state, save_state


def register_assets(app) -> None:
    @app.get("/firmware")
    def firmware():
        state = load_state(app.config["DATA_DIR"])
        latest = latest_by_channel(state)
        rows = []
        for router in state["routers"]:
            facts = router.get("facts") if isinstance(router.get("facts"), dict) else {}
            channel = str(facts.get("channel") or "").strip()
            current = latest.get(channel) or ""
            rows.append(
                {
                    "router": router,
                    "facts": facts,
                    "version": version_label(facts.get("version")),
                    "channel": channel,
                    "outdated": bool(current) and channel in CHANNELS and outdated(facts.get("version"), current),
                }
            )
        return render_template("firmware.html", rows=rows, latest=latest, channels=CHANNELS)

    @app.post("/firmware/latest")
    def firmware_latest():
        state = load_state(app.config["DATA_DIR"])
        stored = latest_by_channel(state)
        missed = []
        for channel in CHANNELS:
            manual = request.form.get(f"latest_{channel}", "").strip()
            if manual:
                stored[channel] = manual
                continue
            try:
                stored[channel] = fetch_latest(channel)
            except Exception:
                missed.append(channel)
        state["firmware_latest"] = stored
        record(state, "firmware", "Saved latest RouterOS versions for " + ", ".join(CHANNELS))
        save_state(app.config["DATA_DIR"], state)
        if missed:
            flash(
                "Could not fetch "
                + ", ".join(missed)
                + ". Type that version, or leave the box blank to try again.",
                "error",
            )
        else:
            flash("Latest versions saved.", "ok")
        return redirect(url_for("firmware"))

    @app.post("/firmware/refresh")
    def firmware_refresh():
        return _refresh(app, "firmware")

    @app.post("/firmware/upgrade")
    def firmware_upgrade():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        ids = set(request.form.getlist("router_ids"))
        targets = [router for router in state["routers"] if router["id"] in ids and router.get("enabled", True)]
        if not targets:
            flash("Select a router to upgrade.", "error")
            return redirect(url_for("firmware"))
        if len(targets) > 1 and request.form.get("confirm_many") != "yes":
            flash("Confirm the upgrade. It reboots more than one router.", "error")
            return redirect(url_for("firmware"))
        try:
            batch = max(1, min(50, int(request.form.get("batch", "1"))))
        except ValueError:
            batch = 1
        try:
            username, password = account_password(state)
        except AutomationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("firmware"))
        channel = request.form.get("channel", "").strip()
        results = upgrade_many(
            targets,
            _connector(app),
            username,
            password,
            data_dir,
            batch,
            channel=channel or None,
        )
        state["last_upgrade"] = {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "routers": results}
        names = ", ".join(f"{item['site_name']} {item['status']}" for item in results)
        record(state, "firmware", f"Firmware upgrade by neill: {names}")
        save_state(data_dir, state)
        flash("Firmware upgrade finished. Routers that started an upgrade will reboot.", "ok")
        return redirect(url_for("firmware"))

    @app.get("/inventory")
    def inventory():
        state = load_state(app.config["DATA_DIR"])
        return render_template("inventory.html", groups=_groups(state["routers"]))

    @app.post("/inventory/refresh")
    def inventory_refresh():
        return _refresh(app, "inventory")

    @app.get("/inventory.csv")
    def inventory_csv():
        state = load_state(app.config["DATA_DIR"])
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["site", "ip", "groups", "model", "serial", "version", "channel", "arch", "uptime", "licence", "enabled"])
        for router in state["routers"]:
            facts = router.get("facts") if isinstance(router.get("facts"), dict) else {}
            writer.writerow(
                [
                    router.get("site_name") or "",
                    router.get("ip") or "",
                    " ".join(router.get("tags") or []),
                    facts.get("model") or "",
                    facts.get("serial") or "",
                    version_label(facts.get("version")),
                    facts.get("channel") or "",
                    facts.get("arch") or "",
                    facts.get("uptime") or "",
                    facts.get("licence") or "",
                    "yes" if router.get("enabled", True) else "no",
                ]
            )
        return Response(
            buffer.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=easy-radius-inventory.csv"},
        )


def _groups(routers: list[dict]) -> list[dict]:
    groups: dict[str, list] = {}
    for router in routers:
        shown = dict(router)
        facts = shown.get("facts") if isinstance(shown.get("facts"), dict) else {}
        shown["facts"] = {**facts, "version": version_label(facts.get("version"))}
        tags = shown.get("tags") or ["Ungrouped"]
        for tag in tags:
            groups.setdefault(tag, []).append(shown)
    return [{"name": name, "routers": groups[name]} for name in sorted(groups)]


def _refresh(app, target: str):
    data_dir = app.config["DATA_DIR"]
    state = load_state(data_dir)
    try:
        username, password = account_password(state)
    except AutomationError as exc:
        flash(str(exc), "error")
        return redirect(url_for(target))
    connector = _connector(app)
    failed = 0
    for router in state["routers"]:
        if router.get("enabled", True) is False:
            continue
        try:
            refresh_router(router, connector, username, password)
        except Exception:
            failed += 1
    record(state, "inventory", "Refreshed router model, version, and uptime")
    save_state(data_dir, state)
    if failed:
        flash(f"Refreshed what answered. {failed} router(s) could not be read.", "error")
    else:
        flash("Router details refreshed.", "ok")
    return redirect(url_for(target))


def _connector(app):
    connector = app.config.get("ROUTER_CONNECT")
    if connector is None:
        from easy_radius.routeros_api import connect_router

        return connect_router
    return connector
