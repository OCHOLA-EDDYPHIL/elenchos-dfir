from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

from siftguard.audit.execution_ledger import append_event, make_event_id, read_events, utc_now
from siftguard.evidence.hashing import sha256_file
from siftguard.policy.tools import is_command_allowed
from siftguard.runner.tool_result import ToolResult


def run_command(
    command: list[str],
    cwd: str | None,
    stdout_path: str | None,
    stderr_path: str | None,
    timeout_seconds: int,
    ledger_path: Path | None = None,
    case_id: str | None = None,
    tool_name: str | None = None,
) -> ToolResult:
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise TypeError("command must be list[str]")

    allowed, reason = is_command_allowed(command)
    if not allowed:
        raise PermissionError(f"command denied: {reason}")

    stdout_handle: Any = subprocess.PIPE
    stderr_handle: Any = subprocess.PIPE
    stdout_file_path: Path | None = None
    stderr_file_path: Path | None = None

    if stdout_path is not None:
        stdout_file_path = Path(stdout_path)
        stdout_file_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_handle = stdout_file_path.open("wb")

    if stderr_path is not None:
        stderr_file_path = Path(stderr_path)
        stderr_file_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_handle = stderr_file_path.open("wb")

    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            timeout=timeout_seconds,
            shell=False,
            stdout=stdout_handle,
            stderr=stderr_handle,
        )
    finally:
        if stdout_file_path is not None:
            stdout_handle.close()
        if stderr_file_path is not None:
            stderr_handle.close()

    duration_ms = int((time.monotonic() - start) * 1000)
    stdout_sha256 = (
        sha256_file(stdout_file_path)
        if stdout_file_path is not None and stdout_file_path.exists()
        else None
    )
    stderr_sha256 = (
        sha256_file(stderr_file_path)
        if stderr_file_path is not None and stderr_file_path.exists()
        else None
    )

    result = ToolResult(
        command=command,
        cwd=cwd,
        exit_code=proc.returncode,
        duration_ms=duration_ms,
        stdout_path=str(stdout_file_path) if stdout_file_path else None,
        stderr_path=str(stderr_file_path) if stderr_file_path else None,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        status="success" if proc.returncode == 0 else "failed",
    )

    if ledger_path is not None:
        events = read_events(ledger_path)
        event = {
            "event_id": make_event_id(len(events) + 1),
            "timestamp_utc": utc_now(),
            "event_type": "tool_execution",
            "case_id": case_id,
            "tool_name": tool_name,
            "command": command,
            "cwd": cwd,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "stdout_path": result.stdout_path,
            "stderr_path": result.stderr_path,
            "stdout_sha256": result.stdout_sha256,
            "stderr_sha256": result.stderr_sha256,
            "status": result.status,
        }
        append_event(ledger_path, event)

    return result
