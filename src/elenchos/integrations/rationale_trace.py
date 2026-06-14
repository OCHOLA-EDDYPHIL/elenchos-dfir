from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from elenchos.audit.execution_ledger import utc_now
from elenchos.integrations.safe_paths import display_path, repo_root
from elenchos.policy.paths import MOUNTED_EVIDENCE_ROOT, is_generated_output_path, is_relative_to

MODEL_RATIONALE_FILENAME = "model_rationale.jsonl"
POLICY_DECISIONS_FILENAME = "policy_decisions.jsonl"
ORCHESTRATION_TRACE_FILENAME = "orchestration_trace.json"
RUN_JOB_FILENAME = "run_job.json"


def _ensure_generated_path(path: Path) -> Path:
    resolved = path.resolve()
    if is_relative_to(resolved, MOUNTED_EVIDENCE_ROOT):
        raise ValueError(f"path must not be under evidence root '{MOUNTED_EVIDENCE_ROOT}'")
    if not is_generated_output_path(resolved):
        raise ValueError("path must be under an ignored generated output directory")
    return resolved


def validate_generated_trace_path(path: Path) -> Path:
    resolved = _ensure_generated_path(path)
    _ensure_generated_path(resolved.parent)
    return resolved


def append_jsonl(path: Path, record: Mapping[str, object]) -> None:
    resolved = validate_generated_trace_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with resolved.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(record), sort_keys=True, separators=(",", ":")))
        handle.write("\n")


def load_json_file(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
    return payload


def safe_read_json(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    try:
        return load_json_file(path)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def iter_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed JSONL at line {lineno} in {path}: {exc.msg}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"malformed JSONL at line {lineno} in {path}: not an object")
            rows.append(payload)
    return rows


def next_sequence_id(prefix: str, jsonl_path: Path) -> str:
    if not prefix:
        raise ValueError("prefix must be non-empty")
    max_seen = 0
    for row in iter_jsonl(jsonl_path):
        for value in row.values():
            if not isinstance(value, str) or not value.startswith(f"{prefix}_"):
                continue
            suffix = value.removeprefix(f"{prefix}_")
            if suffix.isdigit():
                max_seen = max(max_seen, int(suffix))
    return f"{prefix}_{max_seen + 1:06d}"


def agent_run_dir_from_output_dir(output_dir: Path) -> Path:
    resolved = _ensure_generated_path(output_dir)
    if resolved.name == "agent-run":
        return resolved
    nested = resolved / "agent-run"
    if nested.exists():
        return _ensure_generated_path(nested)
    return resolved


def model_rationale_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / MODEL_RATIONALE_FILENAME)


def policy_decisions_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / POLICY_DECISIONS_FILENAME)


def orchestration_trace_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / ORCHESTRATION_TRACE_FILENAME)


def run_job_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / RUN_JOB_FILENAME)


def append_orchestration_event(
    agent_run_dir: Path,
    *,
    event_type: str,
    payload: Mapping[str, object],
) -> dict[str, object]:
    path = orchestration_trace_path(agent_run_dir)
    now = utc_now()
    existing = safe_read_json(path)
    if existing is None:
        trace: dict[str, object] = {
            "schema_version": 1,
            "output_dir": display_path(agent_run_dir),
            "created_at_utc": now,
            "updated_at_utc": now,
            "events": [],
        }
    else:
        trace = dict(existing)
        trace["updated_at_utc"] = now
    events = trace.get("events")
    if not isinstance(events, list):
        events = []
    events.append(
        {
            "timestamp_utc": now,
            "event_type": event_type,
            "payload": dict(payload),
        }
    )
    trace["events"] = events
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return trace


def display_trace_path(path: Path | None) -> str | None:
    if path is None:
        return None
    if is_relative_to(path.resolve(), repo_root()):
        return display_path(path)
    return display_path(path)


def line_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def read_jsonl_tail(path: Path, limit: int = 5) -> list[dict[str, Any]]:
    rows = iter_jsonl(path)
    return rows[-limit:]
