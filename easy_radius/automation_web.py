"""Automation pages. Only a signed-in admin can open them."""

from __future__ import annotations

import secrets

from flask import abort, flash, redirect, render_template, request, url_for

from easy_radius.automation import (
    AutomationError,
    account_password,
    automation_key,
    encrypt_secret,
    ensure_builtins,
    export_path,
    find_task,
    finish_audit,
    launch_run,
    list_runs,
    load_run,
    parse_template,
    save_run,
    select_targets,
    service_account_ready,
)
from easy_radius.audit import record
from easy_radius.store import load_state, save_state
from easy_radius.userhash import assign_user_password
from easy_radius.validate import validate_user


def register_automation(app) -> None:
    @app.get("/automation")
    def automation():
        state = _ready_state(app)
        return render_template(
            "automation.html",
            tasks=state.get("tasks") or [],
            account=state.get("automation_account") or {},
            ready=service_account_ready(state),
            users=state.get("users") or [],
            runs=list_runs(app.config["DATA_DIR"])[:8],
        )

    @app.post("/automation/account")
    def automation_account():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        generate = request.form.get("generate") == "yes"
        group = request.form.get("group", "write")
        existing_id = request.form.get("user_id", "").strip()
        if generate:
            password = secrets.token_urlsafe(18)
        if not password:
            flash("Enter a password, or generate one. It is stored encrypted and is not shown again.", "error")
            return redirect(url_for("automation"))
        if existing_id:
            user = next((item for item in state["users"] if item["id"] == existing_id), None)
            if user is None:
                flash("Choose a user from the list.", "error")
                return redirect(url_for("automation"))
            error = validate_user(user["username"], password, user["group"], state["users"], current_id=user["id"])
            if error:
                flash(error, "error")
                return redirect(url_for("automation"))
            assign_user_password(user, password)
            username = user["username"]
            if user.get("group") == "read":
                flash("This user is in the read group. Changes on the router will be refused until the group is write or full.", "ok")
        else:
            error = validate_user(username, password, group, state["users"])
            if error:
                flash(error, "error")
                return redirect(url_for("automation"))
            if group not in {"write", "full"}:
                flash("Use the write or full group so the account can change a router.", "error")
                return redirect(url_for("automation"))
            user = {
                "id": secrets.token_hex(8),
                "username": username,
                "group": group,
                "enabled": True,
                "access": "all",
                "router_ids": [],
                "access_tags": [],
            }
            assign_user_password(user, password)
            state["users"].append(user)
            record(state, "user.add", f"Added {username} ({group}, All routers) as the automation account")
        key = automation_key(state)
        state["automation_account"] = {
            "user_id": user["id"],
            "username": username,
            "password_enc": encrypt_secret(key, password),
        }
        save_state(data_dir, state)
        flash("Service account saved. Click Apply so FreeRADIUS can answer the router. The password is not shown again.", "ok")
        return redirect(url_for("automation"))

    @app.get("/automation/tasks/new")
    def automation_task_new():
        _ready_state(app)
        return render_template("task_form.html", task={"id": "", "name": "", "body": ""}, error=None, title="New task")

    @app.post("/automation/tasks/new")
    def automation_task_create():
        return _save_task(app, None)

    @app.get("/automation/tasks/<task_id>/edit")
    def automation_task_edit(task_id: str):
        state = _ready_state(app)
        task = find_task(state, task_id)
        if task is None:
            abort(404)
        return render_template("task_form.html", task=task, error=None, title="Edit task")

    @app.post("/automation/tasks/<task_id>/edit")
    def automation_task_update(task_id: str):
        return _save_task(app, task_id)

    @app.post("/automation/tasks/upload")
    def automation_task_upload():
        upload = request.files.get("task")
        if upload is None or not upload.filename:
            flash("Choose a YAML or JSON file.", "error")
            return redirect(url_for("automation"))
        raw = upload.read(_MAX_UPLOAD)
        if len(raw) >= _MAX_UPLOAD:
            flash("That file is too large.", "error")
            return redirect(url_for("automation"))
        try:
            body = raw.decode("utf-8")
            parsed = parse_template(body)
        except UnicodeDecodeError:
            flash("The file must be UTF-8 text.", "error")
            return redirect(url_for("automation"))
        except AutomationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("automation"))
        state = load_state(app.config["DATA_DIR"])
        state.setdefault("tasks", []).append(
            {"id": secrets.token_hex(8), "name": parsed.name, "body": body, "builtin": False}
        )
        record(state, "automation", f"Uploaded task {parsed.name}")
        save_state(app.config["DATA_DIR"], state)
        flash("Task uploaded.", "ok")
        return redirect(url_for("automation"))

    @app.post("/automation/tasks/<task_id>/delete")
    def automation_task_delete(task_id: str):
        state = load_state(app.config["DATA_DIR"])
        task = find_task(state, task_id)
        if task is None:
            abort(404)
        state["tasks"] = [item for item in state["tasks"] if item["id"] != task_id]
        record(state, "automation", f"Deleted task {task['name']}")
        save_state(app.config["DATA_DIR"], state)
        flash("Task deleted.", "ok")
        return redirect(url_for("automation"))

    @app.get("/automation/tasks/<task_id>/run")
    def automation_run_form(task_id: str):
        state = _ready_state(app)
        task = find_task(state, task_id)
        if task is None:
            abort(404)
        try:
            parsed = parse_template(task["body"])
        except AutomationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("automation"))
        tags = []
        for router in state["routers"]:
            for tag in router.get("tags") or []:
                if tag not in tags:
                    tags.append(tag)
        return render_template(
            "automation_run.html",
            task=task,
            variables=parsed.variables,
            routers=[router for router in state["routers"] if router.get("enabled", True)],
            tags=tags,
            ready=service_account_ready(state),
        )

    @app.post("/automation/tasks/<task_id>/run")
    def automation_run_post(task_id: str):
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        task = find_task(state, task_id)
        if task is None:
            abort(404)
        if not service_account_ready(state):
            flash("Set the automation service account first.", "error")
            return redirect(url_for("automation"))
        try:
            parsed = parse_template(task["body"])
            variables = {}
            for name, default in parsed.variables.items():
                variables[name] = request.form.get(f"var_{name}", default)
            targets = select_targets(
                state["routers"],
                request.form.getlist("router_ids"),
                request.form.getlist("tags"),
            )
        except AutomationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("automation_run_form", task_id=task_id))
        if not targets:
            flash("Select a router or a site group.", "error")
            return redirect(url_for("automation_run_form", task_id=task_id))
        mode = request.form.get("mode", "check")
        if mode not in {"check", "run"}:
            mode = "check"
        if len(targets) > 1 and request.form.get("confirm_many") != "yes":
            flash("Confirm the run. It targets more than one router.", "error")
            return redirect(url_for("automation_run_form", task_id=task_id))
        try:
            batch = int(request.form.get("batch", "1"))
        except ValueError:
            batch = 1
        batch = max(1, min(batch, 50))
        try:
            username, password = account_password(state)
        except AutomationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("automation"))
        from datetime import datetime, timezone

        from easy_radius.automation import new_run_id

        run = {
            "id": new_run_id(data_dir),
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": "neill",
            "task_id": task["id"],
            "task_name": task["name"],
            "mode": mode,
            "batch": batch,
            "status": "running",
            "routers": [
                {"id": router["id"], "site_name": router["site_name"], "ip": router["ip"], "status": "waiting", "output": ""}
                for router in targets
            ],
        }
        save_run(data_dir, run)
        connector = app.config.get("ROUTER_CONNECT")
        if connector is None:
            from easy_radius.routeros_api import connect_router

            connector = connect_router

        def on_finished(finished: dict) -> None:
            from easy_radius.automation import note_touches

            current = load_state(data_dir)
            note_touches(current, finished)
            finish_audit(current, finished)
            save_state(data_dir, current)

        launch_run(
            data_dir,
            run,
            parsed,
            variables,
            targets,
            username,
            password,
            connector,
            on_finished,
            inline=bool(app.config.get("TESTING")),
        )
        return redirect(url_for("automation_run_detail", run_id=run["id"]))

    @app.get("/automation/runs/<run_id>")
    def automation_run_detail(run_id: str):
        _ready_state(app)
        run = load_run(app.config["DATA_DIR"], run_id)
        if run is None:
            abort(404)
        return render_template("automation_result.html", run=run)

    @app.get("/automation/runs/<run_id>/exports/<router_id>")
    def automation_export(run_id: str, router_id: str):
        _ready_state(app)
        path = export_path(app.config["DATA_DIR"], run_id, router_id)
        if path is None:
            abort(404)
        text = path.read_text(encoding="utf-8", errors="replace")
        return render_template(
            "automation_export.html",
            run_id=run_id,
            router_id=router_id,
            text=text[:200_000],
            truncated=len(text) > 200_000,
        )

    @app.post("/automation/runs/<run_id>/exports/<router_id>/restore")
    def automation_restore(run_id: str, router_id: str):
        if request.form.get("confirm_restore") != "yes":
            flash("Confirm the restore. It sends the saved export back to that router.", "error")
            return redirect(url_for("automation_export", run_id=run_id, router_id=router_id))
        data_dir = app.config["DATA_DIR"]
        path = export_path(data_dir, run_id, router_id)
        run = load_run(data_dir, run_id)
        if path is None or run is None:
            abort(404)
        router = next((item for item in run.get("routers") or [] if item.get("id") == router_id), None)
        if router is None:
            abort(404)
        state = load_state(data_dir)
        try:
            username, password = account_password(state)
        except AutomationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("automation"))
        connector = app.config.get("ROUTER_CONNECT")
        if connector is None:
            from easy_radius.routeros_api import connect_router

            connector = connect_router
        text = path.read_text(encoding="utf-8", errors="replace")
        session = None
        try:
            session = connector(router["ip"], username, password)
            session.restore(text)
        except Exception as exc:
            message = str(exc)
            if password and password in message:
                message = message.replace(password, "<password>")
            flash(f"Restore failed: {message}", "error")
            return redirect(url_for("automation_export", run_id=run_id, router_id=router_id))
        finally:
            if session is not None and getattr(session, "close", None):
                try:
                    session.close()
                except Exception:
                    pass
        from datetime import datetime, timezone

        touches = dict(state.get("router_touches") or {})
        touches[str(router_id)] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        state["router_touches"] = touches
        record(state, "automation", f"Restored the saved export on {router['site_name']} ({router['ip']})")
        save_state(data_dir, state)
        flash(f"Sent the saved export to {router['site_name']}. A normal export hides secrets, so those values were not restored.", "ok")
        return redirect(url_for("automation_run_detail", run_id=run_id))


_MAX_UPLOAD = 64 * 1024 + 1


def _ready_state(app):
    state = load_state(app.config["DATA_DIR"])
    if ensure_builtins(state):
        save_state(app.config["DATA_DIR"], state)
    return state


def _save_task(app, task_id: str | None):
    data_dir = app.config["DATA_DIR"]
    state = load_state(data_dir)
    name = request.form.get("name", "").strip()
    body = request.form.get("body", "")
    if task_id:
        task = find_task(state, task_id)
        if task is None:
            abort(404)
    else:
        task = None
    try:
        parsed = parse_template(body)
    except AutomationError as exc:
        posted = {"id": task_id or "", "name": name, "body": body}
        return render_template("task_form.html", task=posted, error=str(exc), title="Edit task" if task else "New task"), 400
    if not name:
        name = parsed.name
    if task is None:
        state.setdefault("tasks", []).append(
            {"id": secrets.token_hex(8), "name": name, "body": body, "builtin": False}
        )
        record(state, "automation", f"Added task {name}")
        flash("Task saved.", "ok")
    else:
        task["name"] = name
        task["body"] = body
        record(state, "automation", f"Updated task {name}")
        flash("Task updated.", "ok")
    save_state(data_dir, state)
    return redirect(url_for("automation"))
