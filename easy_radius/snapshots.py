"""Snapshots of the routers and users written by a successful Apply."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SNAPSHOT_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z(?:-[0-9]+)?$")


class SnapshotError(Exception):
    pass


def _directory(data_dir: Path) -> Path:
    path = Path(data_dir) / "snapshots"
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def save_snapshot(data_dir: Path, state: dict) -> str:
    directory = _directory(data_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snap_id = stamp
    suffix = 2
    while (directory / f"{snap_id}.json").exists():
        snap_id = f"{stamp}-{suffix}"
        suffix += 1
    payload = {
        "id": snap_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "routers": json.loads(json.dumps(state.get("routers") or [])),
        "users": json.loads(json.dumps(state.get("users") or [])),
    }
    path = directory / f"{snap_id}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)
    return snap_id


def list_snapshots(data_dir: Path) -> list[dict]:
    directory = Path(data_dir) / "snapshots"
    if not directory.is_dir():
        return []
    found = []
    for path in directory.glob("*.json"):
        snap_id = path.stem
        if not SNAPSHOT_ID.fullmatch(snap_id):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        found.append(
            {
                "id": snap_id,
                "created_at": payload.get("created_at") or snap_id,
                "routers": len(payload.get("routers") or []),
                "users": len(payload.get("users") or []),
            }
        )
    found.sort(key=lambda item: item["id"], reverse=True)
    return found


def load_snapshot(data_dir: Path, snap_id: str) -> dict:
    if not SNAPSHOT_ID.fullmatch(snap_id):
        raise SnapshotError("Unknown snapshot")
    path = Path(data_dir) / "snapshots" / f"{snap_id}.json"
    if not path.is_file():
        raise SnapshotError("Unknown snapshot")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload.get("routers"), list) or not isinstance(payload.get("users"), list):
        raise SnapshotError("Snapshot is incomplete")
    return payload
