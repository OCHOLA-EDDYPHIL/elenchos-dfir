from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from elenchos.audit.execution_ledger import utc_now
from elenchos.integrations.rationale_trace import run_job_path, safe_read_json
from elenchos.integrations.safe_paths import display_path

ACTIVE_JOB_STATUSES = {"starting", "running"}
TERMINAL_JOB_STATUSES = {"completed", "failed", "completed_unknown_exit"}


def process_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_run_job(agent_run_dir: Path) -> dict[str, object] | None:
    return safe_read_json(run_job_path(agent_run_dir))


def write_run_job(agent_run_dir: Path, payload: Mapping[str, object]) -> Path:
    path = run_job_path(agent_run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def is_active_job(payload: Mapping[str, object] | None) -> bool:
    if payload is None:
        return False
    return payload.get("status") in ACTIVE_JOB_STATUSES


def make_job_record(
    *,
    job_id: str,
    case_id: str,
    pid: int,
    output_dir: Path,
    prepared_manifest_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    status: str = "running",
    started_at_utc: str | None = None,
) -> dict[str, object]:
    if status not in ACTIVE_JOB_STATUSES and status not in TERMINAL_JOB_STATUSES:
        raise ValueError(f"invalid job status: {status}")
    return {
        "schema_version": 1,
        "job_id": job_id,
        "case_id": case_id,
        "pid": pid,
        "status": status,
        "started_at_utc": started_at_utc or utc_now(),
        "updated_at_utc": utc_now(),
        "finished_at_utc": None,
        "output_dir": display_path(output_dir),
        "prepared_manifest_path": display_path(prepared_manifest_path),
        "artifact_manifest": display_path(prepared_manifest_path),
        "stdout_path": display_path(stdout_path),
        "stderr_path": display_path(stderr_path),
        "runner": "elenchos agent run-case",
        "shell": False,
    }


def update_job_status(
    agent_run_dir: Path,
    *,
    status: str,
    returncode: int | None = None,
) -> dict[str, object]:
    payload = read_run_job(agent_run_dir)
    if payload is None:
        raise ValueError("run_job.json is missing")
    updated: dict[str, Any] = dict(payload)
    updated["status"] = status
    updated["updated_at_utc"] = utc_now()
    if status in TERMINAL_JOB_STATUSES:
        updated["finished_at_utc"] = utc_now()
    if returncode is not None:
        updated["returncode"] = returncode
    write_run_job(agent_run_dir, updated)
    return updated
