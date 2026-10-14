"""Config backups and compliance pages."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from flask import abort, flash, redirect, render_template, request, url_for

from easy_radius.audit import record
from easy_radius.automation import AutomationError, launch_run, new_run_id, save_run
from easy_radius.compliance import evaluate, fix_template, present_report, score
from easy_radius.config_backups import (
    backup_due,
    complete_backup,
    default_schedule,
    diff_versions,
    list_versions,
    read_version,
)
from easy_radius.store import load_state, save_state

_STARTED = False


def register_ops(app) -> None:
    if not app.config.get("TESTING"):
        _start_backup_thread(app)

    @app.get("/backups")
    def config_backups():
        state = load_state(app.config["DATA_DIR"])
        schedule = {**default_schedule(), **(state.get("backup_schedule") or {})}
        last = state.get("last_backup_run") or {}
        by_id = {row.get("id"): row for row in last.get("routers") or []}
        routers = []
        for router in state.get("routers") or []:
            versions = list_versions(app.config["DATA_DIR"], router["id"])
            previous = by_id.get(router["id"]) or {}
            routers.append(
                {
                    **router,
                    "versions": versions[:20],
                    "last_at": last.get("at") if previous else "",
                    "last_status": previous.get("status") or "",
                    "last_detail": previous.get("detail") or "",
                }
            )
        return render_template(
            "backups.html",
            schedule=schedule,
            routers=routers,
            alerts=state.get("change_alerts") or [],
            backup_run=last,
        )

    @app.post("/backups/settings")
    def config_backup_settings():
        state = load_state(app.config["DATA_DIR"])
        schedule = {**default_schedule(), **(state.get("backup_schedule") or {})}
        schedule["enabled"] = request.form.get("enabled") == "yes"
        try:
            schedule["hour"] = max(0, min(23, int(request.form.get("hour", "2"))))
            schedule["retention_days"] = max(1, min(365, int(request.form.get("retention_days", "30"))))
        except ValueError:
            flash("Hour and retention must be numbers.", "error")
            return redirect(url_for("config_backups"))
        state["backup_schedule"] = schedule
        record(state, "backup.settings", f"Backup schedule hour {schedule['hour']} UTC, keep {schedule['retention_days']} days, enabled {schedule['enabled']}")
        save_state(app.config["DATA_DIR"], state)
        flash("Backup schedule saved.", "ok")
        return redirect(url_for("config_backups"))

    @app.post("/backups/run")
    def config_backup_run():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        summary = complete_backup(state, data_dir, _connector(app), actor="neill")
        save_state(data_dir, state)
        failed = summary.get("error") or any(row.get("status") == "failed" for row in summary.get("routers") or [])
        if failed:
            flash("Some config backups failed.", "error")
        else:
            flash("Config backups finished.", "ok")
        return redirect(url_for("config_backups"))

    @app.get("/backups/<router_id>")
    def config_backup_diff(router_id: str):
        state = load_state(app.config["DATA_DIR"])
        router = next((item for item in state["routers"] if item["id"] == router_id), None)
        if router is None:
            abort(404)
        versions = list_versions(app.config["DATA_DIR"], router_id)
        left = request.args.get("left") or (versions[1] if len(versions) > 1 else "")
        right = request.args.get("right") or (versions[0] if versions else "")
        diff = ""
        error = ""
        if left and right:
            try:
                diff = diff_versions(
                    read_version(app.config["DATA_DIR"], router_id, left),
                    read_version(app.config["DATA_DIR"], router_id, right),
                )
            except AutomationError as exc:
                error = str(exc)
        return render_template(
            "backup_diff.html",
            router=router,
            versions=versions,
            left=left,
            right=right,
            diff=diff or "No difference.",
            error=error,
        )

    @app.get("/compliance")
    def compliance():
        state = load_state(app.config["DATA_DIR"])
        return render_template(
            "compliance.html",
            routers=[router for router in state["routers"] if router.get("enabled", True)],
            report=present_report(state.get("last_compliance")),
        )

    @app.post("/compliance/check")
    def compliance_check():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        connector = _connector(app)
        try:
            username, password = __import__("easy_radius.automation", fromlist=["account_password"]).account_password(state)
        except AutomationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("compliance"))
        rows = []
        for router in state["routers"]:
            if router.get("enabled", True) is False:
                continue
            try:
                session = _open(connector, router, username, password)
            except Exception as exc:
                rows.append({"id": router["id"], "site_name": router["site_name"], "ip": router["ip"], "error": _scrub(str(exc), password), "checks": [], "passed": 0, "total": 0})
                continue
            try:
                checks = evaluate(session, state.get("radius_server_address") or "")
            except Exception as exc:
                rows.append({"id": router["id"], "site_name": router["site_name"], "ip": router["ip"], "error": _scrub(str(exc), password), "checks": [], "passed": 0, "total": 0})
                continue
            finally:
                if getattr(session, "close", None):
                    try:
                        session.close()
                    except Exception:
                        pass
            passed, total = score(checks)
            rows.append({"id": router["id"], "site_name": router["site_name"], "ip": router["ip"], "error": "", "checks": checks, "passed": passed, "total": total})
        state["last_compliance"] = {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "routers": rows}
        record(state, "compliance", "Checked router compliance")
        save_state(data_dir, state)
        flash("Compliance check finished.", "ok")
        return redirect(url_for("compliance"))

    @app.post("/compliance/fix")
    def compliance_fix():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        router_ids = request.form.getlist("router_ids")
        if len(router_ids) > 1 and request.form.get("confirm_many") != "yes":
            flash("Confirm the fix. It changes more than one router.", "error")
            return redirect(url_for("compliance"))
        targets = []
        for router in state["routers"]:
            if router["id"] in router_ids and router.get("enabled", True):
                targets.append(router)
        if not targets:
            flash("Select a router to fix.", "error")
            return redirect(url_for("compliance"))
        try:
            username, password = __import__("easy_radius.automation", fromlist=["account_password"]).account_password(state)
        except AutomationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("compliance"))
        template = fix_template(state.get("radius_server_address") or "")
        run = {
            "id": new_run_id(data_dir),
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": "neill",
            "task_id": "compliance-fix",
            "task_name": "Compliance fix",
            "mode": "run",
            "batch": 1,
            "status": "running",
            "routers": [],
        }
        save_run(data_dir, run)
        connector = _connector(app)

        def on_finished(finished: dict) -> None:
            from easy_radius.automation import finish_audit, note_touches

            current = load_state(data_dir)
            note_touches(current, finished)
            finish_audit(current, finished)
            save_state(data_dir, current)

        launch_run(
            data_dir,
            run,
            template,
            {},
            targets,
            username,
            password,
            connector,
            on_finished,
            inline=bool(app.config.get("TESTING")),
        )
        return redirect(url_for("automation_run_detail", run_id=run["id"]))


def _connector(app):
    connector = app.config.get("ROUTER_CONNECT")
    if connector is None:
        from easy_radius.routeros_api import connect_router

        connector = connect_router
    return connector


def _open(connector, router, username, password):
    allow = bool(router.get("api_plaintext"))
    try:
        return connector(router["ip"], username, password, allow_plaintext=allow)
    except TypeError:
        return connector(router["ip"], username, password)


def _scrub(text: str, password: str) -> str:
    if password and password in text:
        return text.replace(password, "<password>")
    return text


def _start_backup_thread(app) -> None:
    global _STARTED
    if _STARTED:
        return
    _STARTED = True

    def loop() -> None:
        while True:
            time.sleep(60)
            try:
                _maybe_backup(app)
            except Exception:
                continue

    threading.Thread(target=loop, name="easy-radius-backups", daemon=True).start()


def _maybe_backup(app) -> None:
    with app.app_context():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        schedule = {**default_schedule(), **(state.get("backup_schedule") or {})}
        now = datetime.now(timezone.utc)
        if not backup_due(schedule, now):
            return
        complete_backup(state, data_dir, _connector(app), actor="scheduler", now=now)
        save_state(data_dir, state)
