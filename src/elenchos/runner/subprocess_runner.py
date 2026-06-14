from __future__ import annotations

import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO

from elenchos.audit.execution_ledger import (
    append_event,
    make_audit_event,
    make_event_id,
    read_events,
    utc_now,
)
from elenchos.evidence.hashing import sha256_file
from elenchos.policy.paths import assert_not_inside_evidence_output, validate_output_path
from elenchos.policy.tools import is_command_allowed
from elenchos.runner.tool_result import ToolResult


def _validate_output_target(
    output_path: Path,
    runs_root: Path | None,
    evidence_root: Path | None,
) -> Path:
    if runs_root is not None:
        return validate_output_path(output_path, runs_root, evidence_root)

    resolved = output_path.resolve()
    if evidence_root is not None:
        assert_not_inside_evidence_output(resolved, evidence_root)
    return resolved


def _hash_if_present(path: Path | None) -> str | None:
    if path is None or not path.exists() or path.is_dir():
        return None
    return sha256_file(path)


def _append_audit(
    *,
    ledger_path: Path,
    case_id: str | None,
    tool_name: str | None,
    result: ToolResult,
) -> None:
    event_id = make_event_id(len(read_events(ledger_path)) + 1)
    event = make_audit_event(
        event_id=event_id,
        timestamp_utc=utc_now(),
        case_id=case_id,
        tool_name=tool_name,
        command=result.command,
        cwd=result.cwd,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        stdout_path=result.stdout_path,
        stderr_path=result.stderr_path,
        stdout_sha256=result.stdout_sha256,
        stderr_sha256=result.stderr_sha256,
        status=result.status,
    )
    append_event(ledger_path, event)


def run_command(
    command: Sequence[str],
    cwd: Path | None = None,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
    timeout_seconds: int = 300,
    ledger_path: Path | None = None,
    case_id: str | None = None,
    tool_name: str | None = None,
    runs_root: Path | None = None,
    evidence_root: Path | None = None,
) -> ToolResult:
    if isinstance(command, str):
        raise TypeError("command must be a non-empty Sequence[str], not a string")
    if not isinstance(command, Sequence):
        raise TypeError("command must be a non-empty Sequence[str]")
    if len(command) == 0:
        raise ValueError("command must not be empty")
    if not all(isinstance(item, str) for item in command):
        raise TypeError("command must contain only strings")

    command_list = list(command)
    resolved_cwd = str(cwd.resolve()) if cwd is not None else None

    resolved_stdout_path: Path | None = None
    resolved_stderr_path: Path | None = None

    if stdout_path is not None:
        resolved_stdout_path = _validate_output_target(stdout_path, runs_root, evidence_root)
    if stderr_path is not None:
        resolved_stderr_path = _validate_output_target(stderr_path, runs_root, evidence_root)

    allowed, reason = is_command_allowed(command_list)
    if not allowed:
        denied_result = ToolResult(
            command=command_list,
            cwd=resolved_cwd,
            exit_code=-1,
            duration_ms=0,
            stdout_path=str(resolved_stdout_path) if resolved_stdout_path else None,
            stderr_path=str(resolved_stderr_path) if resolved_stderr_path else None,
            stdout_sha256=None,
            stderr_sha256=None,
            status="denied",
        )
        if ledger_path is not None:
            _append_audit(
                ledger_path=ledger_path,
                case_id=case_id,
                tool_name=tool_name or reason,
                result=denied_result,
            )
        return denied_result

    stdout_handle: int | BinaryIO = subprocess.PIPE
    stderr_handle: int | BinaryIO = subprocess.PIPE

    if resolved_stdout_path is not None:
        resolved_stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_handle = resolved_stdout_path.open("wb")

    if resolved_stderr_path is not None:
        resolved_stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_handle = resolved_stderr_path.open("wb")

    start = time.monotonic()
    exit_code = -1
    timed_out = False

    try:
        proc = subprocess.run(
            command_list,
            cwd=resolved_cwd,
            check=False,
            timeout=timeout_seconds,
            shell=False,
            stdout=stdout_handle,
            stderr=stderr_handle,
        )
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        if resolved_stderr_path is not None:
            with resolved_stderr_path.open("ab") as handle:
                timeout_msg = (
                    f"timeout after {timeout_seconds} seconds "
                    f"while executing: {command_list}\n"
                )
                handle.write(
                    timeout_msg.encode("utf-8")
                )
    finally:
        if resolved_stdout_path is not None and not isinstance(stdout_handle, int):
            stdout_handle.close()
        if resolved_stderr_path is not None and not isinstance(stderr_handle, int):
            stderr_handle.close()

    duration_ms = int((time.monotonic() - start) * 1000)
    status = "success" if exit_code == 0 and not timed_out else "failed"

    result = ToolResult(
        command=command_list,
        cwd=resolved_cwd,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout_path=str(resolved_stdout_path) if resolved_stdout_path else None,
        stderr_path=str(resolved_stderr_path) if resolved_stderr_path else None,
        stdout_sha256=_hash_if_present(resolved_stdout_path),
        stderr_sha256=_hash_if_present(resolved_stderr_path),
        status=status,
    )

    if ledger_path is not None:
        _append_audit(ledger_path=ledger_path, case_id=case_id, tool_name=tool_name, result=result)

    return result
