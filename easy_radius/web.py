"""HTTP UI for Easy Radius."""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from easy_radius.apply import apply_configuration, run_radtest
from easy_radius.configgen import sanitise_client_name
from easy_radius.hostcmd import make_runner
from easy_radius.store import check_admin_password, load_state, prepare_state, save_state
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
        RUNNER=runner or make_runner(),
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
        return render_template("login.html", error=None)

    @app.post("/login")
    def login_post():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        state = load_state(app.config["DATA_DIR"])
        if not check_admin_password(state, username, password):
            return render_template("login.html", error="Username or password is not correct."), 401
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
        return render_template("routers.html", routers=state["routers"])

    @app.get("/routers/new")
    def router_new():
        return render_template(
            "router_form.html",
            router={"site_name": "", "ip": "", "secret": secrets.token_hex(16)},
            error=None,
            title="Add router",
        )

    @app.post("/routers/new")
    def router_create():
        state = load_state(app.config["DATA_DIR"])
        site_name = request.form.get("site_name", "")
        ip_text = request.form.get("ip", "")
        secret = request.form.get("secret", "")
        error = validate_router(site_name, ip_text, secret, state["routers"])
        if error:
            return render_template(
                "router_form.html",
                router={"site_name": site_name.strip(), "ip": ip_text.strip(), "secret": secret},
                error=error,
                title="Add router",
            ), 400
        taken = {router["client_name"] for router in state["routers"]}
        ip = canonical_ip(ip_text)
        state["routers"].append(
            {
                "id": secrets.token_hex(8),
                "site_name": site_name.strip(),
                "ip": ip,
                "secret": secret,
                "client_name": sanitise_client_name(site_name.strip(), ip, taken),
            }
        )
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
        error = validate_router(site_name, ip_text, secret, state["routers"], current_id=router_id)
        if error:
            posted = {
                "id": router_id,
                "site_name": site_name.strip(),
                "ip": ip_text.strip(),
                "secret": secret,
            }
            return render_template("router_form.html", router=posted, error=error, title="Edit router"), 400
        taken = {item["client_name"] for item in state["routers"] if item["id"] != router_id}
        ip = canonical_ip(ip_text)
        router["site_name"] = site_name.strip()
        router["ip"] = ip
        router["secret"] = secret
        router["client_name"] = sanitise_client_name(router["site_name"], ip, taken)
        save_state(app.config["DATA_DIR"], state)
        flash("Router updated. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("routers"))

    @app.post("/routers/<router_id>/delete")
    def router_delete(router_id: str):
        state = load_state(app.config["DATA_DIR"])
        before = len(state["routers"])
        state["routers"] = [item for item in state["routers"] if item["id"] != router_id]
        if len(state["routers"]) == before:
            abort(404)
        save_state(app.config["DATA_DIR"], state)
        flash("Router removed. Click Apply to update FreeRADIUS.", "ok")
        return redirect(url_for("routers"))

    @app.get("/users")
    def users():
        state = load_state(app.config["DATA_DIR"])
        return render_template("users.html", users=state["users"])

    @app.get("/users/new")
    def user_new():
        return render_template(
            "user_form.html",
            user={"username": "", "password": "", "group": "write"},
            groups=GROUPS,
            error=None,
            title="Add user",
        )

    @app.post("/users/new")
    def user_create():
        state = load_state(app.config["DATA_DIR"])
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        group = request.form.get("group", "")
        error = validate_user(username, password, group, state["users"])
        if error:
            return render_template(
                "user_form.html",
                user={"username": username.strip(), "password": password, "group": group},
                groups=GROUPS,
                error=error,
                title="Add user",
            ), 400
        state["users"].append(
            {
                "id": secrets.token_hex(8),
                "username": username.strip(),
                "password": password,
                "group": group,
            }
        )
        save_state(app.config["DATA_DIR"], state)
        flash("User saved. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("users"))

    @app.get("/users/<user_id>/edit")
    def user_edit(user_id: str):
        state = load_state(app.config["DATA_DIR"])
        user = _find(state["users"], user_id)
        if user is None:
            abort(404)
        return render_template("user_form.html", user=user, groups=GROUPS, error=None, title="Edit user")

    @app.post("/users/<user_id>/edit")
    def user_update(user_id: str):
        state = load_state(app.config["DATA_DIR"])
        user = _find(state["users"], user_id)
        if user is None:
            abort(404)
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        group = request.form.get("group", "")
        error = validate_user(username, password, group, state["users"], current_id=user_id)
        if error:
            posted = {"id": user_id, "username": username.strip(), "password": password, "group": group}
            return render_template(
                "user_form.html", user=posted, groups=GROUPS, error=error, title="Edit user"
            ), 400
        user["username"] = username.strip()
        user["password"] = password
        user["group"] = group
        save_state(app.config["DATA_DIR"], state)
        flash("User updated. Click Apply before FreeRADIUS uses it.", "ok")
        return redirect(url_for("users"))

    @app.post("/users/<user_id>/delete")
    def user_delete(user_id: str):
        state = load_state(app.config["DATA_DIR"])
        before = len(state["users"])
        state["users"] = [item for item in state["users"] if item["id"] != user_id]
        if len(state["users"]) == before:
            abort(404)
        save_state(app.config["DATA_DIR"], state)
        flash("User removed. Click Apply to update FreeRADIUS.", "ok")
        return redirect(url_for("users"))

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
        )
        state = load_state(data_dir)
        state["last_apply"] = {
            "ok": result.ok,
            "rolled_back": result.rolled_back,
            "restarted": result.restarted,
            "backup_dir": result.backup_dir,
            "output": result.output,
        }
        save_state(data_dir, state)
        return redirect(url_for("apply_page"))

    @app.get("/test")
    def test_page():
        state = load_state(app.config["DATA_DIR"])
        return render_template("test.html", result=state.get("last_test"), username="", password="")

    @app.post("/test")
    def test_post():
        data_dir = app.config["DATA_DIR"]
        state = load_state(data_dir)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Enter the username and password to test.", "error")
            return redirect(url_for("test_page"))
        completed = run_radtest(username, password, state["localhost_secret"], app.config["RUNNER"])
        output = completed.format()
        secret = state["localhost_secret"]
        if secret:
            output = output.replace(secret, "<localhost-secret>")
        state["last_test"] = {"ok": completed.ok, "output": output, "username": username}
        save_state(data_dir, state)
        return redirect(url_for("test_page"))

    return app


def _find(items: list[dict], item_id: str) -> dict | None:
    for item in items:
        if item.get("id") == item_id:
            return item
    return None
