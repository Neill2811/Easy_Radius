"""RouterOS tasks for the routers already stored in Easy Radius.

A task is a short YAML or JSON list of paths to set. The router list and
site-group tags are the inventory. Nothing here shells out to Ansible.
"""

from __future__ import annotations

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from easy_radius.audit import record
from easy_radius.userhash import assign_user_password

_TASKS = Path(__file__).resolve().parent / "tasks"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
_PATH = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9_/-]*$")
_VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z(?:-[0-9]+)?$")
_SAFE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_BODY = 64 * 1024
_AAD = b"easy-radius-automation"
_THREADS: set[str] = set()
_LOCK = threading.Lock()


class AutomationError(Exception):
    pass


@dataclass
class Step:
    path: str
    values: dict[str, str]
    where: dict[str, str] = field(default_factory=dict)


@dataclass
class Template:
    name: str
    variables: dict[str, str]
    steps: list[Step] = field(default_factory=list)


def encrypt_secret(key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    token = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _AAD)
    return "aesgcm$" + nonce.hex() + "$" + token.hex()


def decrypt_secret(key: bytes, stored: str) -> str:
    try:
        kind, nonce_hex, token_hex = stored.split("$", 2)
        if kind != "aesgcm":
            raise ValueError
        nonce = bytes.fromhex(nonce_hex)
        token = bytes.fromhex(token_hex)
        return AESGCM(key).decrypt(nonce, token, _AAD).decode("utf-8")
    except Exception as exc:
        raise AutomationError("The saved service-account password could not be read.") from exc


def automation_key(state: dict) -> bytes:
    import secrets

    raw = state.get("automation_key") or ""
    if len(raw) != 64:
        state["automation_key"] = secrets.token_hex(32)
        raw = state["automation_key"]
    return bytes.fromhex(raw)


def _assignments(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        equals = text.find("=", index)
        if equals < 0 or text[index:equals].strip() == "":
            raise AutomationError(f"Expected name=value in {text!r}")
        key = text[index:equals].strip()
        index = equals + 1
        if text.startswith("{{", index):
            end = text.find("}}", index)
            if end < 0:
                raise AutomationError("A variable placeholder was not closed.")
            values[key] = text[index : end + 2]
            index = end + 2
        elif index < len(text) and text[index] == '"':
            index += 1
            chars: list[str] = []
            while index < len(text) and text[index] != '"':
                if text[index] == "\\" and index + 1 < len(text):
                    chars.append(text[index + 1])
                    index += 2
                else:
                    chars.append(text[index])
                    index += 1
            if index >= len(text) or text[index] != '"':
                raise AutomationError("A quoted value was not closed.")
            index += 1
            values[key] = "".join(chars)
        else:
            end = index
            while end < len(text) and not text[end].isspace():
                end += 1
            values[key] = text[index:end]
            index = end
    if not values:
        raise AutomationError("A set command needs at least one name=value.")
    return values


def _step_from_command(command: str) -> Step:
    match = re.match(r"^(/[A-Za-z0-9][A-Za-z0-9_/-]*)\s+set\s+(.+)$", command.strip())
    if not match:
        raise AutomationError(
            "Write a path and set, for example /ip/dns set servers=192.0.2.53"
        )
    path, rest = match.group(1), match.group(2)
    if not _PATH.fullmatch(path):
        raise AutomationError(f"Unsupported path {path}")
    return Step(path=path, values=_assignments(rest))


def _step_from_mapping(item: dict) -> Step:
    path = str(item.get("path") or "").strip()
    if not _PATH.fullmatch(path):
        raise AutomationError("Each step needs a path like /ip/dns")
    raw = item.get("set")
    if not isinstance(raw, dict) or not raw:
        raise AutomationError(f"{path} needs a set list of values.")
    values = {str(key): "" if value is None else str(value) for key, value in raw.items()}
    where_raw = item.get("where") or {}
    if not isinstance(where_raw, dict):
        raise AutomationError(f"{path} where must be name=value pairs.")
    where = {str(key): "" if value is None else str(value) for key, value in where_raw.items()}
    return Step(path=path, values=values, where=where)


def parse_template(body: str) -> Template:
    if len(body.encode("utf-8")) > _MAX_BODY:
        raise AutomationError("That task is too large.")
    try:
        loaded = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise AutomationError("That task is not valid YAML or JSON.") from exc
    name = "Task"
    variables: dict[str, str] = {}
    raw_steps: list = []
    if isinstance(loaded, dict):
        name = str(loaded.get("name") or name).strip() or name
        raw_vars = loaded.get("variables") or {}
        if not isinstance(raw_vars, dict):
            raise AutomationError("variables must be a list of names and defaults.")
        for key, value in raw_vars.items():
            if not _VAR.fullmatch(str(key)):
                raise AutomationError(f"Unsupported variable name {key}")
            if isinstance(value, dict):
                value = value.get("default", "")
            variables[str(key)] = "" if value is None else str(value)
        raw_steps = loaded.get("steps") if "steps" in loaded else loaded.get("commands")
        if not isinstance(raw_steps, list):
            raise AutomationError("Add a steps list.")
    elif isinstance(loaded, list):
        raw_steps = loaded
    else:
        raise AutomationError("A task is a YAML list of commands, or a name and steps.")
    if not raw_steps or len(raw_steps) > 100:
        raise AutomationError("A task needs between 1 and 100 steps.")
    steps: list[Step] = []
    for item in raw_steps:
        if isinstance(item, str):
            steps.append(_step_from_command(item))
        elif isinstance(item, dict):
            steps.append(_step_from_mapping(item))
        else:
            raise AutomationError("Each step must be a command or a path and set values.")
    return Template(name=name, variables=variables, steps=steps)


def builtin_tasks() -> list[dict]:
    found = []
    for path in sorted(_TASKS.glob("*.yml")):
        body = path.read_text(encoding="utf-8")
        parsed = parse_template(body)
        found.append(
            {
                "id": f"builtin-{path.stem}",
                "name": parsed.name,
                "body": body,
                "builtin": True,
            }
        )
    return found


def ensure_builtins(state: dict) -> bool:
    if state.get("tasks_seeded"):
        return False
    state["tasks"] = list(state.get("tasks") or [])
    if not state["tasks"]:
        state["tasks"] = builtin_tasks()
    state["tasks_seeded"] = True
    return True


def find_task(state: dict, task_id: str) -> dict | None:
    for task in state.get("tasks") or []:
        if task.get("id") == task_id:
            return task
    return None


def substitute(value: str, variables: dict[str, str]) -> str:
    def replacer(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            raise AutomationError(f"Missing value for {name}")
        return variables[name]

    return _PLACE.sub(replacer, value)


def same_value(current: object, desired: str) -> bool:
    left = _canonical(current)
    right = _canonical(desired)
    return left == right


def _canonical(value: object) -> str:
    text = str(value).strip()
    lowered = text.lower()
    if lowered in {"yes", "true"}:
        return "true"
    if lowered in {"no", "false"}:
        return "false"
    return text


def plan_changes(current: dict[str, str], desired: dict[str, str]) -> dict[str, str]:
    changes = {}
    for key, value in desired.items():
        if key.startswith("."):
            raise AutomationError("Step values cannot set internal attributes.")
        if not same_value(current.get(key, ""), value):
            changes[key] = value
    return changes


def render_diff(path: str, current: dict[str, str], changes: dict[str, str]) -> str:
    if not changes:
        return f"{path}: already set"
    lines = [path]
    for key, value in changes.items():
        previous = current.get(key, "(not set)")
        lines.append(f"  {key}: {previous} -> {value}")
    return "\n".join(lines)


def select_targets(routers: list[dict], router_ids: list[str], tags: list[str]) -> list[dict]:
    known = {router["id"]: router for router in routers}
    chosen: list[dict] = []
    seen: set[str] = set()
    for router_id in router_ids:
        router = known.get(router_id)
        if router is None:
            raise AutomationError("Choose routers from the list.")
        if router.get("enabled", True) is False:
            continue
        if router_id not in seen:
            chosen.append(router)
            seen.add(router_id)
    known_tags = {tag for router in routers for tag in (router.get("tags") or [])}
    for tag in tags:
        if tag not in known_tags:
            raise AutomationError(f"Unknown site group {tag}")
    for router in routers:
        if router.get("enabled", True) is False:
            continue
        if router["id"] in seen:
            continue
        if any(tag in tags for tag in (router.get("tags") or [])):
            chosen.append(router)
            seen.add(router["id"])
    return chosen


def _runs_dir(data_dir: Path) -> Path:
    path = Path(data_dir) / "automation" / "runs"
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    os.chmod(path, 0o700)
    return path


def _write_json(path: Path, payload: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)


def save_run(data_dir: Path, run: dict) -> None:
    _write_json(_runs_dir(data_dir) / f"{run['id']}.json", run)


def load_run(data_dir: Path, run_id: str) -> dict | None:
    if not _RUN_ID.fullmatch(run_id):
        return None
    path = _runs_dir(data_dir) / f"{run_id}.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("status") == "running" and run_id not in _THREADS:
        payload["status"] = "failed"
        payload["note"] = "The run stopped because Easy Radius restarted."
        save_run(data_dir, payload)
    return payload


def list_runs(data_dir: Path) -> list[dict]:
    directory = Path(data_dir) / "automation" / "runs"
    if not directory.is_dir():
        return []
    found = []
    for path in directory.glob("*.json"):
        if not _RUN_ID.fullmatch(path.stem):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        found.append(payload)
    found.sort(key=lambda item: item.get("id") or "", reverse=True)
    return found[:50]


def export_path(data_dir: Path, run_id: str, router_id: str) -> Path | None:
    if not _RUN_ID.fullmatch(run_id) or not _SAFE.fullmatch(router_id):
        return None
    path = _runs_dir(data_dir) / run_id / f"{router_id}.rsc"
    if not path.is_file():
        return None
    return path


def new_run_id(data_dir: Path) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = stamp
    suffix = 2
    while (_runs_dir(data_dir) / f"{run_id}.json").exists():
        run_id = f"{stamp}-{suffix}"
        suffix += 1
    return run_id


def _apply_one(session, template: Template, variables: dict[str, str], dry_run: bool, data_dir: Path, run_id: str, router: dict) -> dict:
    output: list[str] = []
    changed = False
    if not dry_run:
        text = session.export()
        folder = _runs_dir(data_dir) / run_id
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, 0o700)
        export_file = folder / f"{router['id']}.rsc"
        fd = os.open(export_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(export_file, 0o600)
        output.append(f"Saved /export ({len(text)} characters). Secrets are hidden.")
    for step in template.steps:
        desired = {key: substitute(value, variables) for key, value in step.values.items()}
        where = {key: substitute(value, variables) for key, value in step.where.items()}
        if where and hasattr(session, "rows"):
            matched = [
                row
                for row in session.rows(step.path)
                if all(same_value(row.get(key), value) for key, value in where.items())
            ]
            if not matched:
                output.append(f"{step.path} {where}: nothing to change")
                continue
            current = {str(key): str(value) for key, value in matched[0].items() if key != ".id"}
        else:
            current = session.get(step.path)
        changes = plan_changes(current, desired)
        label = step.path if not where else f"{step.path} {where}"
        output.append(render_diff(label, current, changes))
        if changes:
            changed = True
            if not dry_run:
                if where and hasattr(session, "set_matching"):
                    session.set_matching(step.path, where, changes)
                else:
                    session.set(step.path, changes)
    status = "changed" if changed else "ok"
    if dry_run and changed:
        output.append("Dry run: nothing was written.")
    return {
        "id": router["id"],
        "site_name": router["site_name"],
        "ip": router["ip"],
        "status": status,
        "output": "\n".join(output),
        "exported": not dry_run,
    }


def _chunks(items: list, size: int):
    for index in range(0, len(items), size):
        yield items[index : index + size]


def execute_run(
    data_dir: Path,
    run: dict,
    template: Template,
    variables: dict[str, str],
    routers: list[dict],
    username: str,
    password: str,
    connector,
) -> dict:
    dry_run = run["mode"] == "check"
    batch = max(1, min(int(run.get("batch") or 1), 50))
    results: list[dict] = []
    stopped = False
    for wave in _chunks(routers, batch):
        if stopped:
            break
        wave_results: list[dict | None] = [None] * len(wave)

        def work(index: int, router: dict) -> None:
            try:
                session = _connect(connector, router, username, password)
            except Exception as exc:
                wave_results[index] = {
                    "id": router["id"],
                    "site_name": router["site_name"],
                    "ip": router["ip"],
                    "status": "failed",
                    "output": _public_error(exc, password),
                }
                return
            try:
                wave_results[index] = _apply_one(
                    session, template, variables, dry_run, data_dir, run["id"], router
                )
            except Exception as exc:
                wave_results[index] = {
                    "id": router["id"],
                    "site_name": router["site_name"],
                    "ip": router["ip"],
                    "status": "failed",
                    "output": _public_error(exc, password),
                }
            finally:
                close = getattr(session, "close", None)
                if close:
                    try:
                        close()
                    except Exception:
                        pass

        if batch == 1 or len(wave) == 1:
            for index, router in enumerate(wave):
                work(index, router)
                results.append(wave_results[index])
                if wave_results[index]["status"] == "failed":
                    stopped = True
                    break
        else:
            with ThreadPoolExecutor(max_workers=min(batch, len(wave))) as pool:
                futures = [pool.submit(work, index, router) for index, router in enumerate(wave)]
                for future in as_completed(futures):
                    future.result()
            results.extend(item for item in wave_results if item is not None)
            if any(item["status"] == "failed" for item in wave_results if item):
                stopped = True
        run["routers"] = list(results)
        save_run(data_dir, run)
    if stopped:
        seen = {item["id"] for item in results}
        for router in routers:
            if router["id"] in seen:
                continue
            results.append(
                {
                    "id": router["id"],
                    "site_name": router["site_name"],
                    "ip": router["ip"],
                    "status": "skipped",
                    "output": "Not started. An earlier router failed.",
                }
            )
    run["routers"] = results
    if any(item["status"] == "failed" for item in results):
        run["status"] = "failed"
    elif stopped:
        run["status"] = "stopped"
    else:
        run["status"] = "ok"
    run["finished_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    save_run(data_dir, run)
    return run


def _public_error(exc: Exception, password: str) -> str:
    text = str(exc) or exc.__class__.__name__
    return _scrub_password(text, password)


def _scrub_password(text: str, password: str) -> str:
    if password:
        text = text.replace(password, "<password>")
    return text


def launch_run(
    data_dir: Path,
    run: dict,
    template: Template,
    variables: dict[str, str],
    routers: list[dict],
    username: str,
    password: str,
    connector,
    on_finished,
    inline: bool,
) -> None:
    def job() -> None:
        with _LOCK:
            _THREADS.add(run["id"])
        try:
            execute_run(data_dir, run, template, variables, routers, username, password, connector)
            on_finished(load_run(data_dir, run["id"]) or run)
        except Exception as exc:
            run["status"] = "failed"
            run["note"] = _public_error(exc, password)
            save_run(data_dir, run)
            on_finished(run)
        finally:
            with _LOCK:
                _THREADS.discard(run["id"])

    if inline:
        job()
    else:
        threading.Thread(target=job, daemon=True).start()


def _connect(connector, router: dict, username: str, password: str):
    allow = bool(router.get("api_plaintext"))
    try:
        return connector(router["ip"], username, password, allow_plaintext=allow)
    except TypeError:
        return connector(router["ip"], username, password)


def note_touches(state: dict, run: dict) -> None:
    """Remember routers this app changed, so a later backup can ignore them."""
    if run.get("mode") != "run":
        return
    when = run.get("finished_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    touches = dict(state.get("router_touches") or {})
    for router in run.get("routers") or []:
        if router.get("status") == "changed":
            touches[str(router.get("id"))] = when
    state["router_touches"] = touches


def finish_audit(state: dict, run: dict) -> None:
    parts = [
        f"{'Checked' if run['mode'] == 'check' else 'Ran'} {run['task_name']} on {len(run['routers'])} routers"
    ]
    for router in run["routers"]:
        label = router["status"]
        if run["mode"] == "check" and label == "changed":
            label = "would change"
        parts.append(f"{router['site_name']} {label}")
    record(state, "automation", ". ".join(parts) + ".", actor=run.get("actor") or "neill")


def account_password(state: dict) -> tuple[str, str]:
    account = state.get("automation_account") or {}
    username = str(account.get("username") or "")
    stored = str(account.get("password_enc") or "")
    if not username or not stored:
        raise AutomationError("Set the automation service account first.")
    key = bytes.fromhex(state.get("automation_key") or "")
    return username, decrypt_secret(key, stored)


def service_account_ready(state: dict) -> bool:
    account = state.get("automation_account") or {}
    return bool(account.get("username") and account.get("password_enc"))
