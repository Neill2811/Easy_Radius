"""Run FreeRADIUS commands on the host.

Inside the container, commands go through nsenter into PID 1's namespaces
so they affect the host's FreeRADIUS. Outside the container they run directly.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


NSENTER_PREFIX = ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--"]


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def format(self) -> str:
        shown = " ".join(self.args)
        parts = [f"$ {shown}", f"exit {self.returncode}"]
        if self.stdout:
            parts.append(self.stdout.rstrip("\n"))
        if self.stderr:
            parts.append(self.stderr.rstrip("\n"))
        return "\n".join(parts)


def use_nsenter() -> bool:
    return os.environ.get("RADIUS_ADMIN_USE_NSENTER", "0") == "1"


def make_runner(enabled: bool | None = None):
    if enabled is None:
        enabled = use_nsenter()

    def run(args: list[str], timeout: int = 120) -> CommandResult:
        command = [*NSENTER_PREFIX, *args] if enabled else list(args)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            return CommandResult(args=list(args), returncode=127, stdout="", stderr=str(exc))
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + f"\nCommand timed out after {timeout}s"
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "replace")
            return CommandResult(args=list(args), returncode=124, stdout=stdout, stderr=stderr)
        return CommandResult(
            args=list(args),
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )

    return run
