from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import IO, Callable, Mapping

from elenchos.integrations.job_state import (
    is_active_job,
    make_job_record,
    process_exists,
    read_run_job,
    update_job_status,
    write_run_job,
)
from elenchos.integrations.rationale_trace import (
    agent_run_dir_from_output_dir,
    append_orchestration_event,
    run_job_path,
)
from elenchos.integrations.safe_paths import (
    display_path,
    evidence_roots_from_case_prep,
    repo_root,
    require_json_path,
    resolve_user_path,
    validate_integration_output_dir,
)
from elenchos.parser.paths import validate_parser_path_identifier
from elenchos.progress import (
    append_progress_event,
    progress_path_for_output_dir,
    read_progress_events,
)
from elenchos.triage import SUPPORTED_EVENT_SELECTION_PROFILES

DEFAULT_MAX_ITERATIONS = 10
DEFAULT_MAX_NORMALIZED_EVENTS = 5000
DEFAULT_EVENT_SELECTION_PROFILE = "forensic-triage"

PopenFactory = Callable[..., subprocess.Popen[str]]
POPEN_REGISTRY: dict[str, subprocess.Popen[str]] = {}


def _required_string(request: Mapping[str, object], name: str) -> str:
    value = request.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_string(request: Mapping[str, object], name: str) -> str | None:
    value = request.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string when provided")
    return value


def _positive_int(request: Mapping[str, object], name: str, default: int) -> int:
    value = request.get(name, default)
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _event_selection_profile(request: Mapping[str, object]) -> str:
    value = request.get("event_selection_profile", DEFAULT_EVENT_SELECTION_PROFILE)
    if not isinstance(value, str) or value not in SUPPORTED_EVENT_SELECTION_PROFILES:
        allowed = ", ".join(sorted(SUPPORTED_EVENT_SELECTION_PROFILES))
        raise ValueError(f"event_selection_profile must be one of: {allowed}")
    return value


def _case_id_from_manifest(path: Path) -> str | None:
    try:
        import json

        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    case_id = payload.get("case_id")
    return case_id if isinstance(case_id, str) and case_id else None


def _case_id(request: Mapping[str, object], artifact_manifest: Path) -> str:
    value = _optional_string(request, "case_id") or _case_id_from_manifest(artifact_manifest)
    if value is None:
        raise ValueError("case_id is required when artifact_manifest has no case_id")
    return validate_parser_path_identifier(value, "case_id")


def _next_job_id(existing: Mapping[str, object] | None) -> str:
    if existing is None:
        return "job_000001"
    value = existing.get("job_id")
    if not isinstance(value, str) or not value.startswith("job_"):
        return "job_000001"
    suffix = value.removeprefix("job_")
    if not suffix.isdigit():
        return "job_000001"
    return f"job_{int(suffix) + 1:06d}"


def _build_run_case_argv(
    *,
    request: Mapping[str, object],
    artifact_manifest: Path,
    output_dir: Path,
    case_id: str,
) -> list[str]:
    max_iterations = _positive_int(request, "max_iterations", DEFAULT_MAX_ITERATIONS)
    max_normalized_events = _positive_int(
        request,
        "max_normalized_events",
        DEFAULT_MAX_NORMALIZED_EVENTS,
    )
    event_selection_profile = _event_selection_profile(request)
    argv = [
        sys.executable,
        "-m",
        "elenchos",
        "agent",
        "run-case",
        "--case-id",
        case_id,
        "--artifact-manifest",
        str(artifact_manifest),
        "--output-dir",
        str(output_dir),
        "--max-iterations",
        str(max_iterations),
        "--max-normalized-events",
        str(max_normalized_events),
        "--event-selection-profile",
        event_selection_profile,
    ]
    casebook_text = _optional_string(request, "casebook")
    if casebook_text is not None:
        casebook = resolve_user_path(casebook_text, "casebook")
        require_json_path(casebook, "casebook")
        argv.extend(["--casebook", str(casebook)])
    return argv


def start_case_run(
    request: Mapping[str, object],
    *,
    popen_factory: PopenFactory = subprocess.Popen,
) -> dict[str, object]:
    artifact_manifest = resolve_user_path(
        _required_string(request, "artifact_manifest"),
        "artifact_manifest",
    )
    require_json_path(artifact_manifest, "artifact_manifest")
    forbidden_roots = (
        evidence_roots_from_case_prep(artifact_manifest)
        if artifact_manifest.exists()
        else []
    )
    output_dir = validate_integration_output_dir(
        _required_string(request, "output_dir"),
        forbidden_roots=forbidden_roots,
    )
    agent_run_dir = agent_run_dir_from_output_dir(output_dir)
    existing = read_run_job(agent_run_dir)
    if is_active_job(existing):
        return {
            "status": "rejected",
            "reason": "an active run job is already recorded",
            "active_job": existing,
            "output_dir": display_path(agent_run_dir),
        }

    case_id = _case_id(request, artifact_manifest)
    argv = _build_run_case_argv(
        request=request,
        artifact_manifest=artifact_manifest,
        output_dir=agent_run_dir,
        case_id=case_id,
    )
    trace_dir = agent_run_dir / "openclaw-trace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = trace_dir / "start_case_run.stdout"
    stderr_path = trace_dir / "start_case_run.stderr"
    stdout_handle: IO[str]
    stderr_handle: IO[str]
    stdout_handle = stdout_path.open("w", encoding="utf-8")
    stderr_handle = stderr_path.open("w", encoding="utf-8")
    try:
        process = popen_factory(
            argv,
            cwd=repo_root(),
            text=True,
            stdout=stdout_handle,
            stderr=stderr_handle,
            shell=False,
        )
    finally:
        stdout_handle.close()
        stderr_handle.close()

    job_id = _next_job_id(existing)
    job = make_job_record(
        job_id=job_id,
        case_id=case_id,
        pid=int(process.pid),
        output_dir=agent_run_dir,
        artifact_manifest=artifact_manifest,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        status="running",
    )
    write_run_job(agent_run_dir, job)
    POPEN_REGISTRY[job_id] = process
    append_progress_event(
        progress_path_for_output_dir(agent_run_dir),
        case_id=case_id,
        phase="run_case",
        status="started",
        message="run_case started",
    )
    append_orchestration_event(
        agent_run_dir,
        event_type="start_case_run",
        payload={"job_id": job_id, "pid": int(process.pid), "status": "running"},
    )
    return {
        "status": "started",
        "job_id": job_id,
        "pid": int(process.pid),
        "case_id": case_id,
        "output_dir": display_path(agent_run_dir),
        "agent_run_dir": display_path(agent_run_dir),
        "run_job": display_path(run_job_path(agent_run_dir)),
        "trace_stdout": display_path(stdout_path),
        "trace_stderr": display_path(stderr_path),
    }


def poll_case_run(request: Mapping[str, object]) -> dict[str, object]:
    output_dir = agent_run_dir_from_output_dir(
        resolve_user_path(_required_string(request, "output_dir"), "output_dir")
    )
    job = read_run_job(output_dir)
    if job is None:
        return {
            "status": "not_found",
            "output_dir": display_path(output_dir),
            "progress_event_count": len(
                read_progress_events(progress_path_for_output_dir(output_dir))
            ),
        }
    status = str(job.get("status", "unknown"))
    job_id = job.get("job_id")
    process = POPEN_REGISTRY.get(job_id) if isinstance(job_id, str) else None
    if process is not None:
        returncode = process.poll()
        if returncode is not None and status in {"starting", "running"}:
            status = "completed" if returncode == 0 else "failed"
            job = update_job_status(output_dir, status=status, returncode=returncode)
    elif status in {"starting", "running"}:
        pid = job.get("pid")
        if isinstance(pid, int) and not process_exists(pid):
            job = update_job_status(output_dir, status="completed_unknown_exit")
            status = str(job["status"])
    progress_path = progress_path_for_output_dir(output_dir)
    return {
        "status": status,
        "job": job,
        "output_dir": display_path(output_dir),
        "run_job": display_path(run_job_path(output_dir)),
        "progress_trace": display_path(progress_path) if progress_path.exists() else None,
        "progress_event_count": len(read_progress_events(progress_path)),
        "generated_outputs": {
            name: display_path(output_dir / name)
            for name in (
                "agent_run.json",
                "findings.json",
                "case_questions.json",
                "report.md",
                "validation_summary.json",
            )
            if (output_dir / name).exists()
        },
    }


def finish_case_run(request: Mapping[str, object]) -> dict[str, object]:
    poll = poll_case_run(request)
    status = poll.get("status")
    output_dir = agent_run_dir_from_output_dir(
        resolve_user_path(_required_string(request, "output_dir"), "output_dir")
    )
    if status in {"running", "starting"}:
        return {
            "status": "running",
            "reason": "run job is still active",
            "output_dir": display_path(output_dir),
            "job": poll.get("job"),
        }
    append_orchestration_event(
        output_dir,
        event_type="finish_case_run",
        payload={"status": str(status)},
    )
    return {
        "status": "completed" if status in {"completed", "completed_unknown_exit"} else status,
        "job": poll.get("job"),
        "output_dir": display_path(output_dir),
        "progress_event_count": poll.get("progress_event_count", 0),
        "generated_outputs": poll.get("generated_outputs", {}),
    }
