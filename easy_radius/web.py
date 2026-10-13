"""HTTP UI for Easy Radius."""

from __future__ import annotations

import os
import secrets
import time
from datetime import timedelta
from io import BytesIO
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from easy_radius.access import access_label, parse_tags
from easy_radius.apply import apply_configuration, run_radtest
from easy_radius.audit import record
from easy_radius.backup import BackupError, apply_payload, decrypt_backup, encrypt_backup, export_payload
from easy_radius.configgen import sanitise_client_name
from easy_radius.hostcmd import make_runner
from easy_radius.logs import (
    filter_auth,
    format_age,
    format_time,
    packet_times,
    parse_acct_log,
    parse_auth_log,
    router_health,
    session_view,
    tail_text,
)
from easy_radius.mikrotik import mikrotik_commands
from easy_radius.snapshots import SnapshotError, list_snapshots, load_snapshot, save_snapshot
from easy_radius.store import check_admin_password, load_state, prepare_state, save_state
from easy_radius.totp import generate_secret, provisioning_uri, verify_totp
from easy_radius.validate import canonical_ip, validate_router, validate_user

GROUPS = ("full", "write", "read")


def create_app(data_dir: str | Path | None = None, runner=None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    data_path = Path(
        data_dir
        or os.environ.get("RADIUS_ADMIN_DATA_DIR")
        or Path(__file__).resolve().parent.parent / "data"
    )
    state = prepare_state(data_path)
    app.secret_key = state["secret_key"]
    app.config.update(
        DATA_DIR=data_path,
        CLIENTS_CONF=Path(
            os.environ.get("RADIUS_ADMIN_CLIENTS_CONF", "/etc/freeradius/3.0/clients.conf")
        ),
        USERS_FILE=Path(
            os.environ.get(
                "RADIUS_ADMIN_USERS_FILE",
                "/etc/freeradius/3.0/mods-config/files/authorize",
            )
        ),
        POLICY_FILE=Path(
            os.environ.get(
                "RADIUS_ADMIN_POLICY_FILE",
                "/etc/freeradius/3.0/policy.d/easy_radius",
            )
        ),
        AUTH_LOG=Path(
            os.environ.get("RADIUS_ADMIN_AUTH_LOG", "/var/log/freeradius/easy-radius-auth.log")
        ),
        ACCT_LOG=Path(
            os.environ.get("RADIUS_ADMIN_ACCT_LOG", "/var/log/freeradius/easy-radius-acct.log")
        ),
        HEALTH_SECONDS=int(os.environ.get("RADIUS_ADMIN_HEALTH_SECONDS", "900")),
        RUNNER=runner or make_runner(),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("RADIUS_ADMIN_COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    )

    @app.after_request
    def security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.before_request
    def csrf_and_auth():
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if (
                not token
                or not expected
                or len(token) != len(expected)
                or not secrets.compare_digest(token, expected)
            ):
                abort(400, "Missing or invalid form token. Reload the page and try again.")
        if request.endpoint in {None, "static", "login", "login_post"}:
            return None
        if not session.get("admin"):
            return redirect(url_for("login"))
        return None

    @app.context_processor
    def inject_csrf():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf_token"]}

    @app.get("/login")
    def login():
        if session.get("admin"):
            return redirect(url_for("routers"))
        return render_template("login.html", error=None, need_code=bool(session.get("pending_2fa")))

    @app.post("/login")
    def login_post():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        code = request.form.get("code", "")
        state = load_state(app.config["DATA_DIR"])
        password_ok = check_admin_password(state, username, password)
        if not password_ok:
            session.pop("pending_2fa", None)
            return render_template("login.html", error="Username or password is not correct.", need_code=False), 401
        if state.get("totp_enabled"):
            if not code:
                session["pending_2fa"] = True
                return render_template(
                    "login.html",
                    error="Enter the code from your authenticator app.",
                    need_code=True,
                )
            if session.get("totp_fails", 0) >= 8:
                session.clear()
                return render_template(
                    "login.html",
                    error="Too many codes. Sign in again.",
                    need_code=False,
                ), 401
            if not verify_totp(state.get("totp_secret") or "", code):
                session["totp_fails"] = session.get("totp_fails", 0) + 1
                session["pending_2fa"] = True
                return render_template("login.html", error="That code is not correct.", need_code=True), 401
        session.clear()
        session["admin"] = "neill"
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return redirect(url_for("routers"))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def index():
        return redirect(url_for("routers"))

    @app.get("/routers")
    def routers():
        state = load_state(app.config["DATA_DIR"])
        return render_template("routers.html", routers=_decorate_routers(app, state), server_address=state["radius_server_address"])

    @app.post("/settings/server-address")
    def server_address():
        state = load_state(app.config["DATA_DIR"])
        value = request.form.get("radius_server_address", "").strip()
        if value:
            error = None
            try:
                canonical_ip(value)
            except ValueError:
                error = "Enter the IPv4 or IPv6 address of this RADIUS server."
            if error:
                flash(error, "error")
                return redirect(url_for("routers"))
            value = canonical_ip(value)
        state["radius_server_address"] = value
        record(state, "settings", f"Set RADIUS server address to {value or '(blank)'}")
        save_state(app.config["DATA_DIR"], state)
        flash("Server address saved.", "ok")
        return redirect(url_for("routers"))

    @app.get("/routers/new")
    def router_new():
        return render_template(
            "router_form.html",
            router={"site_name": "", "ip": "", "secret": secrets.token_hex(16), "tags": []},
            error=None,
            title="Add router",
        )

    @app.post("/routers/new")
    def router_create():
        state = load_state(app.config["DATA_DIR"])
        site_name = request.form.get("site_name", "")
        ip_text = request.form.get("ip", "")
        secret = request.form.get("secret", "")
        tags, tag_error = parse_tags(request.form.get("tags", ""))
        error = tag_error or validate_router(site_name, ip_text, secret, state["routers"])
        if error:
            return render_template(
                "router_form.html",
                router={"site_name": site_name.strip(), "ip": ip_text.strip(), "secret": secret, "tags": tags},
                error=error,
                title="Add router",
            ), 400
        taken = {router["client_name"] for router in state["routers"]}
        ip = canonical_ip(ip_text)
        site = site_name.strip()
        state["routers"].append(
            {
                "id": secrets.token_hex(8),
                "site_name": site,
                "ip": ip,
                "secret": secret,
                "client_name": sanitise_client_name(site, ip, taken),
                "enabled": True,
                "tags": tags,
            }
        )
        record(state, "router.add", f"Added {site} ({ip})")
        save_state(app.config["DATA_DIR"], state)
        flash("Router saved. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("routers"))

    @app.get("/routers/<router_id>/edit")
    def router_edit(router_id: str):
        state = load_state(app.config["DATA_DIR"])
        router = _find(state["routers"], router_id)
        if router is None:
            abort(404)
        return render_template("router_form.html", router=router, error=None, title="Edit router")

    @app.post("/routers/<router_id>/edit")
    def router_update(router_id: str):
        state = load_state(app.config["DATA_DIR"])
        router = _find(state["routers"], router_id)
        if router is None:
            abort(404)
        site_name = request.form.get("site_name", "")
        ip_text = request.form.get("ip", "")
        secret = request.form.get("secret", "")
        tags, tag_error = parse_tags(request.form.get("tags", ""))
        error = tag_error or validate_router(site_name, ip_text, secret, state["routers"], current_id=router_id)
        if error:
            posted = {
                "id": router_id,
                "site_name": site_name.strip(),
                "ip": ip_text.strip(),
                "secret": secret,
                "enabled": router.get("enabled", True),
                "tags": tags,
            }
            return render_template("router_form.html", router=posted, error=error, title="Edit router"), 400
        taken = {item["client_name"] for item in state["routers"] if item["id"] != router_id}
        ip = canonical_ip(ip_text)
        router["site_name"] = site_name.strip()
        router["ip"] = ip
        router["secret"] = secret
        router["tags"] = tags
        router["client_name"] = sanitise_client_name(router["site_name"], ip, taken)
        record(state, "router.edit", f"Updated {router['site_name']} ({ip})")
        save_state(app.config["DATA_DIR"], state)
        flash("Router updated. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("routers"))

    @app.post("/routers/<router_id>/enabled")
    def router_enabled(router_id: str):
        state = load_state(app.config["DATA_DIR"])
        router = _find(state["routers"], router_id)
        if router is None:
            abort(404)
        enabled = request.form.get("enabled") == "1"
        router["enabled"] = enabled
        verb = "Enabled" if enabled else "Disabled"
        record(state, "router.enable" if enabled else "router.disable", f"{verb} {router['site_name']} ({router['ip']})")
        save_state(app.config["DATA_DIR"], state)
        flash(f"{verb} {router['site_name']}. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("routers"))

    @app.get("/users")
    def users():
        state = load_state(app.config["DATA_DIR"])
        shown = []
        for user in state["users"]:
            row = dict(user)
            row["access_label"] = access_label(user, state["routers"])
            shown.append(row)
        return render_template("users.html", users=shown)

    @app.get("/users/new")
    def user_new():
        state = load_state(app.config["DATA_DIR"])
        return render_template(
            "user_form.html",
            user={"username": "", "password": "", "group": "write", "access": "all", "router_ids": [], "access_tags": []},
            groups=GROUPS,
            routers=state["routers"],
            tags=_known_tags(state),
            error=None,
            title="Add user",
        )

    @app.post("/users/new")
    def user_create():
        state = load_state(app.config["DATA_DIR"])
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        group = request.form.get("group", "")
        access, router_ids, access_tags, access_error = _read_access(request, state)
        error = access_error or validate_user(username, password, group, state["users"])
        posted = {
            "username": username.strip(),
            "password": password,
            "group": group,
            "access": access,
            "router_ids": router_ids,
            "access_tags": access_tags,
        }
        if error:
            return render_template(
                "user_form.html",
                user=posted,
                groups=GROUPS,
                routers=state["routers"],
                tags=_known_tags(state),
                error=error,
                title="Add user",
            ), 400
        name = username.strip()
        state["users"].append(
            {
                "id": secrets.token_hex(8),
                "username": name,
                "password": password,
                "group": group,
                "enabled": True,
                "access": access,
                "router_ids": router_ids,
                "access_tags": access_tags,
            }
        )
        record(state, "user.add", f"Added {name} ({group}, {access_label(state['users'][-1], state['routers'])})")
        save_state(app.config["DATA_DIR"], state)
        flash("User saved. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("users"))

    @app.get("/users/<user_id>/edit")
    def user_edit(user_id: str):
        state = load_state(app.config["DATA_DIR"])
        user = _find(state["users"], user_id)
        if user is None:
            abort(404)
        return render_template(
            "user_form.html",
            user=user,
            groups=GROUPS,
            routers=state["routers"],
            tags=_known_tags(state),
            error=None,
            title="Edit user",
        )

    @app.post("/users/<user_id>/edit")
    def user_update(user_id: str):
        state = load_state(app.config["DATA_DIR"])
        user = _find(state["users"], user_id)
        if user is None:
            abort(404)
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        group = request.form.get("group", "")
        access, router_ids, access_tags, access_error = _read_access(request, state)
        error = access_error or validate_user(username, password, group, state["users"], current_id=user_id)
        if error:
            posted = {
                "id": user_id,
                "username": username.strip(),
                "password": password,
                "group": group,
                "enabled": user.get("enabled", True),
                "access": access,
                "router_ids": router_ids,
                "access_tags": access_tags,
            }
            return render_template(
                "user_form.html",
                user=posted,
                groups=GROUPS,
                routers=state["routers"],
                tags=_known_tags(state),
                error=error,
                title="Edit user",
            ), 400
        user["username"] = username.strip()
        user["password"] = password
        user["group"] = group
        user["access"] = access
        user["router_ids"] = router_ids
        user["access_tags"] = access_tags
        record(state, "user.edit", f"Updated {user['username']} ({group}, {access_label(user, state['routers'])})")
        save_state(app.config["DATA_DIR"], state)
        flash("User updated. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("users"))

    @app.post("/users/<user_id>/enabled")
    def user_enabled(user_id: str):
        state = load_state(app.config["DATA_DIR"])
        user = _find(state["users"], user_id)
        if user is None:
            abort(404)
        enabled = request.form.get("enabled") == "1"
        user["enabled"] = enabled
        verb = "Enabled" if enabled else "Disabled"
        record(state, "user.enable" if enabled else "user.disable", f"{verb} {user['username']}")
        save_state(app.config["DATA_DIR"], state)
        flash(f"{verb} {user['username']}. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("users"))

    @app.get("/logins")
    def logins():
        state = load_state(app.config["DATA_DIR"])
        events = parse_auth_log(tail_text(app.config["AUTH_LOG"]))
        user_q = request.args.get("user", "")
        nas = request.args.get("router", "")
        result = request.args.get("result", "")
        if result not in {"", "Access-Accept", "Access-Reject"}:
            result = ""
        shown = filter_auth(events, user=user_q, nas=nas, result=result)[:200]
        names = _router_names(state)
        for event in shown:
            event["when"] = format_time(event["time"])
            event["router"] = names.get(_ip_key(event["nas"]), event["nas"])
        return render_template(
            "logins.html",
            events=shown,
            routers=state["routers"],
            user_q=user_q,
            router_q=nas,
            result_q=result,
            log_path=str(app.config["AUTH_LOG"]),
            has_log=app.config["AUTH_LOG"].is_file(),
        )

    @app.get("/sessions")
    def sessions():
        state = load_state(app.config["DATA_DIR"])
        events = parse_acct_log(tail_text(app.config["ACCT_LOG"]))
        online, history = session_view(events)
        names = _router_names(state)
        for row in online:
            row["when"] = format_time(row["start"])
            row["last_seen"] = format_time(row["last"])
            row["router"] = names.get(_ip_key(row["nas"]), row["nas"])
        history = history[:200]
        for row in history:
            row["when"] = format_time(row["time"])
            row["router"] = names.get(_ip_key(row["nas"]), row["nas"])
        return render_template(
            "sessions.html",
            online=online,
            history=history,
            log_path=str(app.config["ACCT_LOG"]),
            has_log=app.config["ACCT_LOG"].is_file(),
        )

    @app.get("/apply")
    def apply_page():
        state = load_state(app.config["DATA_DIR"])
        return render_template("apply.html", result=state.get("last_apply"))

    @app.post("/apply")
    def apply_post():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        result = apply_configuration(
            state,
            app.config["RUNNER"],
            app.config["CLIENTS_CONF"],
            app.config["USERS_FILE"],
            Path(data_dir) / "backups",
            app.config["POLICY_FILE"],
        )
        state = load_state(data_dir)
        state["last_apply"] = {
            "ok": result.ok,
            "rolled_back": result.rolled_back,
            "restarted": result.restarted,
            "backup_dir": result.backup_dir,
            "output": result.output,
        }
        if result.ok:
            snap_id = save_snapshot(data_dir, state)
            record(state, "apply", f"Applied configuration, snapshot {snap_id}")
        else:
            record(state, "apply", "Apply failed and the previous files were restored")
        save_state(data_dir, state)
        return redirect(url_for("apply_page"))

    @app.get("/history")
    def history():
        state = load_state(app.config["DATA_DIR"])
        events = list(reversed(state.get("audit") or []))
        return render_template(
            "history.html",
            events=events[:200],
            snapshots=list_snapshots(app.config["DATA_DIR"]),
        )

    @app.post("/history/<snap_id>/rollback")
    def history_rollback(snap_id: str):
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        try:
            snapshot = load_snapshot(data_dir, snap_id)
        except SnapshotError:
            abort(404)
        previous_routers = state["routers"]
        previous_users = state["users"]
        state["routers"] = snapshot["routers"]
        state["users"] = snapshot["users"]
        save_state(data_dir, state)
        result = apply_configuration(
            load_state(data_dir),
            app.config["RUNNER"],
            app.config["CLIENTS_CONF"],
            app.config["USERS_FILE"],
            Path(data_dir) / "backups",
            app.config["POLICY_FILE"],
        )
        state = load_state(data_dir)
        state["last_apply"] = {
            "ok": result.ok,
            "rolled_back": result.rolled_back,
            "restarted": result.restarted,
            "backup_dir": result.backup_dir,
            "output": result.output,
        }
        if result.ok:
            record(state, "rollback", f"Restored snapshot {snap_id}")
            save_state(data_dir, state)
            flash(f"Restored snapshot {snap_id} and applied it.", "ok")
            return redirect(url_for("history"))
        state["routers"] = previous_routers
        state["users"] = previous_users
        record(state, "rollback", f"Rollback of {snap_id} failed and was not kept")
        save_state(data_dir, state)
        flash("Rollback did not apply. FreeRADIUS rejected the snapshot, so nothing was changed.", "error")
        return redirect(url_for("apply_page"))

    @app.get("/test")
    def test_page():
        state = load_state(app.config["DATA_DIR"])
        return render_template(
            "test.html",
            result=state.get("last_test"),
            username="",
            password="",
            routers=[router for router in state["routers"] if router.get("enabled", True)],
            nas_ip="",
        )

    @app.post("/test")
    def test_post():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        nas_ip = request.form.get("nas_ip", "").strip()
        if not username or not password:
            flash("Enter the username and password to test.", "error")
            return redirect(url_for("test_page"))
        if nas_ip and not any(router["ip"] == nas_ip and router.get("enabled", True) for router in state["routers"]):
            flash("Choose a router from the list.", "error")
            return redirect(url_for("test_page"))
        completed = run_radtest(username, password, state["localhost_secret"], app.config["RUNNER"], nas_ip=nas_ip)
        output = completed.format()
        secret = state["localhost_secret"]
        if secret:
            output = output.replace(secret, "<localhost-secret>")
        if password:
            output = output.replace(password, "<password>")
        state["last_test"] = {"ok": completed.ok, "output": output, "username": username}
        save_state(data_dir, state)
        return redirect(url_for("test_page"))

    @app.get("/backup")
    def backup_page():
        return render_template("backup.html")

    @app.post("/backup/download")
    def backup_download():
        passphrase = request.form.get("passphrase", "")
        state = load_state(app.config["DATA_DIR"])
        try:
            blob = encrypt_backup(export_payload(state), passphrase)
        except BackupError as exc:
            flash(str(exc), "error")
            return redirect(url_for("backup_page"))
        record(state, "backup", "Downloaded an encrypted backup")
        save_state(app.config["DATA_DIR"], state)
        return send_file(
            BytesIO(blob),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name="easy-radius-backup.erbackup",
        )

    @app.post("/backup/restore")
    def backup_restore():
        upload = request.files.get("backup")
        passphrase = request.form.get("passphrase", "")
        if upload is None or not upload.filename:
            flash("Choose a backup file.", "error")
            return redirect(url_for("backup_page"))
        blob = upload.read(2 * 1024 * 1024 + 1)
        if len(blob) > 2 * 1024 * 1024:
            flash("That file is too large.", "error")
            return redirect(url_for("backup_page"))
        try:
            payload = decrypt_backup(blob, passphrase)
        except BackupError as exc:
            flash(str(exc), "error")
            return redirect(url_for("backup_page"))
        state = load_state(app.config["DATA_DIR"])
        try:
            apply_payload(state, payload)
        except BackupError as exc:
            flash(str(exc), "error")
            return redirect(url_for("backup_page"))
        record(state, "backup.restore", "Restored an encrypted backup")
        save_state(app.config["DATA_DIR"], state)
        flash("Backup restored. Click Apply to write it to FreeRADIUS.", "ok")
        return redirect(url_for("routers"))

    @app.get("/security")
    def security():
        state = load_state(app.config["DATA_DIR"])
        pending = state.get("totp_pending_secret") or ""
        return render_template(
            "security.html",
            enabled=bool(state.get("totp_enabled")),
            pending=pending,
            otpauth=provisioning_uri(pending) if pending else "",
        )

    @app.post("/security/start")
    def security_start():
        state = load_state(app.config["DATA_DIR"])
        if state.get("totp_enabled"):
            return redirect(url_for("security"))
        state["totp_pending_secret"] = generate_secret()
        save_state(app.config["DATA_DIR"], state)
        return redirect(url_for("security"))

    @app.post("/security/confirm")
    def security_confirm():
        state = load_state(app.config["DATA_DIR"])
        pending = state.get("totp_pending_secret") or ""
        code = request.form.get("code", "")
        if not pending or not verify_totp(pending, code):
            flash("That code does not match. Check the clock and try again.", "error")
            return redirect(url_for("security"))
        state["totp_secret"] = pending
        state["totp_pending_secret"] = ""
        state["totp_enabled"] = True
        record(state, "security", "Turned on authenticator codes")
        save_state(app.config["DATA_DIR"], state)
        flash("Authenticator codes are on. You will need a code the next time you sign in.", "ok")
        return redirect(url_for("security"))

    @app.post("/security/disable")
    def security_disable():
        state = load_state(app.config["DATA_DIR"])
        code = request.form.get("code", "")
        if not state.get("totp_enabled") or not verify_totp(state.get("totp_secret") or "", code):
            flash("That code is not correct.", "error")
            return redirect(url_for("security"))
        state["totp_enabled"] = False
        state["totp_secret"] = ""
        state["totp_pending_secret"] = ""
        record(state, "security", "Turned off authenticator codes")
        save_state(app.config["DATA_DIR"], state)
        flash("Authenticator codes are off.", "ok")
        return redirect(url_for("security"))

    return app


def _known_tags(state: dict) -> list[str]:
    tags: list[str] = []
    for router in state["routers"]:
        for tag in router.get("tags") or []:
            if tag not in tags:
                tags.append(tag)
    return tags


def _read_access(req, state: dict) -> tuple[str, list[str], list[str], str | None]:
    access = req.form.get("access", "all")
    if access not in {"all", "routers"}:
        return "all", [], [], "Choose all routers or a chosen list."
    known = {router["id"] for router in state["routers"]}
    router_ids = []
    for router_id in req.form.getlist("router_ids"):
        if router_id not in known:
            return access, [], [], "Choose routers from the list."
        if router_id not in router_ids:
            router_ids.append(router_id)
    known_tags = set(_known_tags(state))
    access_tags = []
    for tag in req.form.getlist("access_tags"):
        if tag not in known_tags:
            return access, router_ids, [], "Choose site groups from the list."
        if tag not in access_tags:
            access_tags.append(tag)
    return access, router_ids, access_tags, None


def _find(items: list[dict], item_id: str) -> dict | None:
    for item in items:
        if item.get("id") == item_id:
            return item
    return None


def _ip_key(value: str) -> str:
    try:
        import ipaddress

        return ipaddress.ip_address(value).compressed
    except ValueError:
        return value


def _router_names(state: dict) -> dict[str, str]:
    names = {}
    for router in state["routers"]:
        names[_ip_key(router["ip"])] = router["site_name"]
    return names


def _decorate_routers(app: Flask, state: dict) -> list[dict]:
    auth = parse_auth_log(tail_text(app.config["AUTH_LOG"]))
    acct = parse_acct_log(tail_text(app.config["ACCT_LOG"]))
    now = int(time.time())
    health = {
        row["id"]: row
        for row in router_health(
            state["routers"],
            packet_times(auth, acct),
            now,
            app.config["HEALTH_SECONDS"],
        )
    }
    server = state.get("radius_server_address") or ""
    decorated = []
    for router in state["routers"]:
        row = dict(router)
        status = health.get(router["id"], {})
        row["up"] = bool(status.get("up"))
        row["seen"] = format_age(status.get("age"))
        row["mikrotik"] = mikrotik_commands(server, router["secret"]) if server else ""
        decorated.append(row)
    return decorated
