from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ALLOWED_STATUSES = {"success", "failed", "denied"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def make_event_id(counter: int) -> str:
    if counter <= 0:
        raise ValueError("counter must be >= 1")
    return f"evt_{counter:06d}"


def make_audit_event(
    *,
    event_id: str,
    timestamp_utc: str,
    case_id: str | None,
    tool_name: str | None,
    command: list[str],
    cwd: str | None,
    exit_code: int,
    duration_ms: int,
    stdout_path: str | None,
    stderr_path: str | None,
    stdout_sha256: str | None,
    stderr_sha256: str | None,
    status: str,
) -> dict[str, Any]:
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"invalid audit status: {status}")
    if not timestamp_utc.endswith("Z"):
        raise ValueError("timestamp_utc must end with Z")

    return {
        "event_id": event_id,
        "timestamp_utc": timestamp_utc,
        "case_id": case_id,
        "tool_name": tool_name,
        "command": list(command),
        "cwd": cwd,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "status": status,
    }


def append_event(ledger_path: Path, event: Mapping[str, Any]) -> None:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(event)
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def read_events(ledger_path: Path) -> list[dict[str, Any]]:
    if not ledger_path.exists():
        return []

    rows: list[dict[str, Any]] = []
    with ledger_path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Malformed JSONL at line {lineno} in '{ledger_path}': {exc.msg}"
                ) from exc
            if not isinstance(payload, dict):
                raise ValueError(
                    f"Malformed JSONL at line {lineno} in '{ledger_path}': not an object"
                )
            rows.append(payload)

    return rows
