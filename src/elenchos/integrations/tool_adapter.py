from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from elenchos.audit.execution_ledger import utc_now
from elenchos.config.runtime import (
    DEFAULT_PREPARE_CASE_TIMEOUT_SECONDS,
    get_prepare_case_timeout_seconds,
)
from elenchos.integrations.job_runner import (
    finish_case_run as finish_case_run_job,
)
from elenchos.integrations.job_runner import (
    poll_case_run as poll_case_run_job,
)
from elenchos.integrations.job_runner import (
    start_case_run as start_case_run_job,
)
from elenchos.integrations.prepared_manifest import resolve_prepared_manifest_path
from elenchos.integrations.rationale_policy import evaluate_action_policy as evaluate_policy
from elenchos.integrations.rationale_schema import ModelRationaleRecord
from elenchos.integrations.rationale_trace import (
    agent_run_dir_from_output_dir,
    append_jsonl,
    append_orchestration_event,
    model_rationale_path,
    next_sequence_id,
)
from elenchos.integrations.run_state import inspect_run_state as inspect_generated_run_state
from elenchos.integrations.safe_paths import (
    display_path,
    evidence_roots_from_case_prep,
    evidence_roots_from_source_manifest,
    repo_root,
    require_json_path,
    resolve_user_path,
    validate_generated_read_dir,
    validate_integration_output_dir,
    validate_source_manifest_out,
)
from elenchos.parser.paths import validate_parser_path_identifier
from elenchos.policy.paths import is_generated_output_path, is_relative_to
from elenchos.progress import (
    append_progress_event,
    progress_path_for_output_dir,
    read_progress_events,
)
from elenchos.triage import SUPPORTED_EVENT_SELECTION_PROFILES
from elenchos.validation.integrity import (
    INTEGRITY_MANIFEST_NAME,
    validate_integrity_manifest,
)

DEFAULT_RUN_CASE_TIMEOUT_SECONDS = 1800
DEFAULT_SUMMARY_TIMEOUT_SECONDS = 60
DEFAULT_MAX_ITERATIONS = 10
DEFAULT_MAX_NORMALIZED_EVENTS = 5000
DEFAULT_EVENT_SELECTION_PROFILE = "forensic-triage"

REQUIRED_RUN_OUTPUTS = (
    "agent_run.json",
    "audit.jsonl",
    "decision_trace.json",
    "gap_analysis.json",
    "self_correction_events.json",
    "performance_summary.json",
    "findings.json",
    "case_questions.json",
    "normalized_events.json",
    "report.md",
    INTEGRITY_MANIFEST_NAME,
)

FORBIDDEN_REPORT_PHRASES = (
    "confirmed compromise",
    "confirmed theft",
    "confirmed exfiltration",
    "confirmed malware execution",
    "proved compromise",
    "proved " "theft",
    "proved " "exfiltration",
)

REGISTRY_USER_ACTIVITY_TYPES = {
    "userassist",
    "recentdocs",
    "opensavepidlmru",
    "lastvisitedpidlmru",
    "typedpaths",
    "registry_user_activity",
}

REDACTED_PATH = "<redacted_path>"
POSIX_PATH_PATTERN = re.compile(r"(?<![:/])/[^\s\"'<>|;]+")
PATH_TRAILING_PUNCTUATION = ".,:)]}"

CommandRunner = Callable[[list[str], int | None], subprocess.CompletedProcess[str]]
SELF_POLICY_GATED_TOOLS = {
    "prepare_case",
    "run_case",
    "summarize_run",
    "validate_run_outputs",
    "inspect_run_state",
    "start_case_run",
    "poll_case_run",
    "finish_case_run",
    "emit_claim_boundary",
}


def _string_schema(description: str) -> dict[str, object]:
    return {"type": "string", "description": description}


def _optional_string_schema(description: str) -> dict[str, object]:
    return {"anyOf": [{"type": "string"}, {"type": "null"}], "description": description}


def _integer_schema(description: str, default: int, minimum: int = 1) -> dict[str, object]:
    return {
        "type": "integer",
        "minimum": minimum,
        "default": default,
        "description": description,
    }


def _prepare_timeout_schema() -> dict[str, object]:
    return {
        "anyOf": [{"type": "integer", "minimum": 0}, {"type": "null"}],
        "default": DEFAULT_PREPARE_CASE_TIMEOUT_SECONDS,
        "description": (
            "Maximum prepare runtime in seconds. Null or 0 disables the adapter-level "
            "prepare timeout; parser subprocesses remain separately bounded."
        ),
    }


def _path_output_schema() -> dict[str, object]:
    return {"anyOf": [{"type": "string"}, {"type": "null"}]}


TOOL_DEFINITIONS: dict[str, dict[str, object]] = {
    "prepare_case": {
        "name": "prepare_case",
        "title": "Prepare Case",
        "description": (
            "Prepare supported Elenchos case artifacts from a source root or JSON source "
            "manifest. This tool invokes the deterministic CLI with typed arguments and "
            "never passes raw evidence contents to a model."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "case_id": _optional_string_schema(
                    "Optional case identifier. Defaults to a generated human-readable ID."
                ),
                "source_root": _optional_string_schema(
                    "Source root to discover; mutually exclusive with source_manifest."
                ),
                "source_manifest": _optional_string_schema(
                    "Existing Elenchos JSON source manifest."
                ),
                "output_dir": _string_schema("Generated case-prep output directory."),
                "source_manifest_out": _optional_string_schema(
                    "Optional JSON source manifest output path for source-root mode."
                ),
                "timeout_seconds": _prepare_timeout_schema(),
            },
            "required": ["output_dir"],
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "status": {"type": "string"},
                "command_name": {"type": "string"},
                "case_id": {"type": "string"},
                "output_dir": {"type": "string"},
                "case_prep": _path_output_schema(),
                "prepared_manifest_path": _path_output_schema(),
                "source_manifest": _path_output_schema(),
                "extraction_audit": _path_output_schema(),
                "prepared_artifact_count": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
                "coverage_gap_count": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
                "duration_ms": {"type": "integer"},
                "trace_stdout": {"type": "string"},
                "trace_stderr": {"type": "string"},
            },
        },
        "annotations": {"readOnlyHint": False},
    },
    "run_case": {
        "name": "run_case",
        "title": "Run Case",
        "description": (
            "Run Elenchos' deterministic agent run-case workflow from a prepared "
            "case manifest. The model can request this bounded tool, but Elenchos "
            "computes evidence-backed outputs."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "case_id": _optional_string_schema(
                    "Optional case identifier. Defaults to case_id in case_prep.json."
                ),
                "prepared_manifest_path": _optional_string_schema(
                    "Stable path to prepared case_prep.json from prepare_case."
                ),
                "artifact_manifest": _optional_string_schema(
                    "Backward-compatible path to case_prep.json."
                ),
                "output_dir": _string_schema("Generated agent output directory."),
                "casebook": _optional_string_schema("Optional JSON casebook path."),
                "max_iterations": _integer_schema(
                    "Hard cap on deterministic agent attempts.",
                    DEFAULT_MAX_ITERATIONS,
                ),
                "max_normalized_events": _integer_schema(
                    "Bounded normalized event cap.",
                    DEFAULT_MAX_NORMALIZED_EVENTS,
                ),
                "event_selection_profile": {
                    "type": "string",
                    "enum": sorted(SUPPORTED_EVENT_SELECTION_PROFILES),
                    "default": DEFAULT_EVENT_SELECTION_PROFILE,
                    "description": "Bounded event selection policy.",
                },
                "timeout_seconds": _integer_schema(
                    "Maximum run-case runtime in seconds.",
                    DEFAULT_RUN_CASE_TIMEOUT_SECONDS,
                ),
            },
            "required": ["output_dir"],
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "status": {"type": "string"},
                "command_name": {"type": "string"},
                "case_id": {"type": "string"},
                "output_dir": {"type": "string"},
                "report": _path_output_schema(),
                "findings": _path_output_schema(),
                "audit": _path_output_schema(),
                "decision_trace": _path_output_schema(),
                "case_questions": _path_output_schema(),
                "gap_analysis": _path_output_schema(),
                "self_correction_events": _path_output_schema(),
                "performance_summary": _path_output_schema(),
                "integrity_manifest": _path_output_schema(),
                "duration_ms": {"type": "integer"},
                "trace_stdout": {"type": "string"},
                "trace_stderr": {"type": "string"},
            },
        },
        "annotations": {"readOnlyHint": False},
    },
    "summarize_run": {
        "name": "summarize_run",
        "title": "Summarize Run",
        "description": (
            "Read generated Elenchos JSON/report outputs only and return a concise "
            "OpenClaw-friendly summary. This tool does not read raw evidence."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"output_dir": _string_schema("Generated run output directory.")},
            "required": ["output_dir"],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": True},
    },
    "validate_run_outputs": {
        "name": "validate_run_outputs",
        "title": "Validate Run Outputs",
        "description": (
            "Validate required generated Elenchos outputs, report wording, and "
            "unsupported not_assessed question safety. This tool reads generated "
            "outputs only."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"output_dir": _string_schema("Generated run output directory.")},
            "required": ["output_dir"],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": True},
    },
    "inspect_run_state": {
        "name": "inspect_run_state",
        "title": "Inspect Generated Run State",
        "description": (
            "Read generated Elenchos outputs only and summarize current run state, "
            "recommended bounded actions, and claim-boundary needs. This tool never "
            "reads raw evidence."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"output_dir": _string_schema("Generated run output directory.")},
            "required": ["output_dir"],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": True},
    },
    "record_model_rationale": {
        "name": "record_model_rationale",
        "title": "Record Model Rationale",
        "description": (
            "Append model-generated operational rationale to model_rationale.jsonl. "
            "Model rationale is not forensic evidence and cannot change findings."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "output_dir": _string_schema("Generated run output directory."),
                "phase": _string_schema("Orchestration phase."),
                "visible_message": _string_schema("Visible [model-rationale] message."),
                "proposed_action": _string_schema("Bounded action proposed by the model."),
                "rationale_summary": _string_schema("Operational rationale summary."),
                "basis_files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "observed_state": {
                    "anyOf": [{"type": "object"}, {"type": "null"}],
                    "default": None,
                },
                "forbidden_claims_avoided": {
                    "anyOf": [
                        {"type": "array", "items": {"type": "string"}},
                        {"type": "null"},
                    ],
                    "default": None,
                },
                "confidence": _string_schema("Operational confidence label."),
            },
            "required": [
                "output_dir",
                "phase",
                "visible_message",
                "proposed_action",
                "rationale_summary",
                "basis_files",
                "confidence",
            ],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": False},
    },
    "evaluate_action_policy": {
        "name": "evaluate_action_policy",
        "title": "Evaluate Action Policy",
        "description": (
            "Evaluate a proposed model action against the deterministic Elenchos "
            "allow/reject policy and append policy_decisions.jsonl. No arbitrary "
            "shell or raw evidence inspection is permitted."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "output_dir": _string_schema("Generated run output directory."),
                "proposed_action": _string_schema("Proposed bounded action."),
                "action_args": {
                    "anyOf": [{"type": "object"}, {"type": "null"}],
                    "default": None,
                },
                "rationale_id": _optional_string_schema("Optional rationale_id."),
            },
            "required": ["output_dir", "proposed_action"],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": False},
    },
    "start_case_run": {
        "name": "start_case_run",
        "title": "Start Case Run",
        "description": (
            "Start the deterministic Elenchos run-case workflow asynchronously with "
            "a fixed argv builder, shell=False, generated output logs, and duplicate "
            "active-job rejection. Use prepared_manifest_path from prepare_case or "
            "inspect_run_state; run_integrity_manifest.json is not a prepared case "
            "manifest."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "case_id": _optional_string_schema(
                    "Optional case identifier. Defaults to case_id in case_prep.json."
                ),
                "prepared_manifest_path": _optional_string_schema(
                    "Stable path to prepared case_prep.json from prepare_case or inspect_run_state."
                ),
                "artifact_manifest": _optional_string_schema(
                    "Backward-compatible path to case_prep.json."
                ),
                "output_dir": _string_schema("Generated agent output directory."),
                "casebook": _optional_string_schema("Optional JSON casebook path."),
                "max_iterations": _integer_schema(
                    "Hard cap on deterministic agent attempts.",
                    DEFAULT_MAX_ITERATIONS,
                ),
                "max_normalized_events": _integer_schema(
                    "Bounded normalized event cap.",
                    DEFAULT_MAX_NORMALIZED_EVENTS,
                ),
                "event_selection_profile": {
                    "type": "string",
                    "enum": sorted(SUPPORTED_EVENT_SELECTION_PROFILES),
                    "default": DEFAULT_EVENT_SELECTION_PROFILE,
                    "description": "Bounded event selection policy.",
                },
            },
            "required": ["output_dir"],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": False},
    },
    "poll_case_run": {
        "name": "poll_case_run",
        "title": "Poll Case Run",
        "description": (
            "Read run_job.json, progress.jsonl, and generated outputs only to report "
            "live deterministic run status."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"output_dir": _string_schema("Generated run output directory.")},
            "required": ["output_dir"],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": True},
    },
    "finish_case_run": {
        "name": "finish_case_run",
        "title": "Finish Case Run",
        "description": (
            "Confirm asynchronous deterministic run completion and return generated "
            "output state without killing processes or reading raw evidence."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"output_dir": _string_schema("Generated run output directory.")},
            "required": ["output_dir"],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": False},
    },
    "emit_claim_boundary": {
        "name": "emit_claim_boundary",
        "title": "Emit Claim Boundary",
        "description": (
            "Return safe claim-boundary wording from generated Elenchos outputs when "
            "present, otherwise return conservative fallback wording. This does not "
            "modify findings or upgrade statuses."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"output_dir": _string_schema("Generated run output directory.")},
            "required": ["output_dir"],
        },
        "outputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": True},
    },
}


def get_tool_definitions() -> list[dict[str, object]]:
    return [TOOL_DEFINITIONS[name] for name in sorted(TOOL_DEFINITIONS)]


def _default_command_runner(
    argv: list[str],
    timeout_seconds: int | None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=repo_root(),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout_seconds,
    )


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


def _utc_case_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slugify_case_label(value: str | None) -> str:
    text = (value or "case").strip().casefold()
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return slug or "case"


def _case_id_from_json_path(path: Path) -> str | None:
    if not path.exists():
        return None
    payload = _read_json_object(path, "case manifest")
    case_id = payload.get("case_id")
    return case_id if isinstance(case_id, str) and case_id else None


def _generated_case_id(*, source_root: Path | None, source_manifest: Path | None) -> str:
    base = None
    if source_manifest is not None:
        base = _case_id_from_json_path(source_manifest)
    if base is None and source_root is not None:
        base = source_root.name
    return validate_parser_path_identifier(
        f"{_slugify_case_label(base)}-{_utc_case_timestamp()}",
        "case_id",
    )


def _case_id_from_request_or_generated(
    request: Mapping[str, object],
    *,
    source_root: Path | None,
    source_manifest: Path | None,
) -> str:
    case_id = _optional_string(request, "case_id")
    if case_id is None:
        return _generated_case_id(source_root=source_root, source_manifest=source_manifest)
    return validate_parser_path_identifier(case_id, "case_id")


def _case_id_from_request_or_manifest(
    request: Mapping[str, object],
    artifact_manifest: Path,
) -> str:
    case_id = _optional_string(request, "case_id")
    if case_id is None:
        manifest_case_id = _case_id_from_json_path(artifact_manifest)
        if manifest_case_id is None:
            raise ValueError("case_id is required when artifact_manifest has no case_id")
        case_id = manifest_case_id
    return validate_parser_path_identifier(case_id, "case_id")


def _positive_int(request: Mapping[str, object], name: str, default: int) -> int:
    value = request.get(name, default)
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _optional_timeout_int(request: Mapping[str, object], name: str) -> int | None:
    value = request.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, null, or omitted")
    return value


def _event_selection_profile(request: Mapping[str, object]) -> str:
    value = request.get("event_selection_profile", DEFAULT_EVENT_SELECTION_PROFILE)
    if not isinstance(value, str) or value not in SUPPORTED_EVENT_SELECTION_PROFILES:
        allowed = ", ".join(sorted(SUPPORTED_EVENT_SELECTION_PROFILES))
        raise ValueError(f"event_selection_profile must be one of: {allowed}")
    return value


def _parse_key_value_stdout(stdout: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            parsed[key] = value.strip()
    return parsed


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed {label} JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} JSON must contain an object")
    return payload


def _write_trace(
    *,
    output_dir: Path,
    operation_name: str,
    stdout: str,
    stderr: str,
) -> tuple[Path, Path]:
    trace_dir = output_dir / "openclaw-trace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = trace_dir / f"{operation_name}.stdout"
    stderr_path = trace_dir / f"{operation_name}.stderr"
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    return stdout_path, stderr_path


def _model_safe_path_token(path_text: str) -> str:
    try:
        resolved = Path(path_text).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return REDACTED_PATH
    if is_generated_output_path(resolved) or is_relative_to(resolved, repo_root()):
        return display_path(resolved) or REDACTED_PATH
    return REDACTED_PATH


def sanitize_model_error(message: object) -> str:
    text = str(message)

    def replace_path(match: re.Match[str]) -> str:
        raw_path = match.group(0)
        path_text = raw_path.rstrip(PATH_TRAILING_PUNCTUATION)
        trailing = raw_path[len(path_text) :]
        if not path_text:
            return raw_path
        return f"{_model_safe_path_token(path_text)}{trailing}"

    return POSIX_PATH_PATTERN.sub(replace_path, text)


def _error_summary(*, returncode: int, stdout: str, stderr: str) -> str:
    text = "\n".join(part for part in (stderr.strip(), stdout.strip()) if part)
    if not text:
        return f"command exited with status {returncode}"
    return sanitize_model_error(text.splitlines()[0][:500])


def _error_payload(exc: Exception) -> dict[str, object]:
    return {"status": "failed", "error": sanitize_model_error(exc)}


def _string_list_request(request: Mapping[str, object], name: str) -> list[str]:
    value = request.get(name, [])
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of strings")
    if not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{name} must contain only non-empty strings")
    return list(value)


def _optional_string_list_request(request: Mapping[str, object], name: str) -> list[str]:
    value = request.get(name)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of strings when provided")
    if not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{name} must contain only non-empty strings")
    return list(value)


def _optional_object_request(request: Mapping[str, object], name: str) -> dict[str, Any]:
    value = request.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object when provided")
    return dict(value)


def _path_from_stdout_or_default(
    parsed: Mapping[str, str],
    key: str,
    default_path: Path,
) -> Path | None:
    value = parsed.get(key)
    if value:
        return Path(value).resolve()
    if default_path.exists():
        return default_path.resolve()
    return None


def _findings_status_counts(output_dir: Path) -> dict[str, int]:
    payload = _read_json_object(output_dir / "findings.json", "findings")
    rows = payload.get("findings", [])
    if not isinstance(rows, list):
        return {}
    counts: Counter[str] = Counter()
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("status"), str):
            counts[row["status"]] += 1
    return dict(sorted(counts.items()))


def _case_question_status_counts(output_dir: Path) -> dict[str, int]:
    payload = _read_json_object(output_dir / "case_questions.json", "case_questions")
    counts = payload.get("status_counts")
    if isinstance(counts, dict):
        return {
            str(key): int(value)
            for key, value in sorted(counts.items())
            if isinstance(value, int)
        }
    questions = payload.get("questions", [])
    if not isinstance(questions, list):
        return {}
    counter: Counter[str] = Counter()
    for question in questions:
        if isinstance(question, dict) and isinstance(question.get("status"), str):
            counter[question["status"]] += 1
    return dict(sorted(counter.items()))


def _parser_status_summary(output_dir: Path) -> dict[str, Any]:
    payload = _read_json_object(output_dir / "coverage_summary.json", "coverage_summary")
    per_artifact = payload.get("per_artifact", [])
    status_counts: Counter[str] = Counter()
    artifact_type_counts: Counter[str] = Counter()
    if isinstance(per_artifact, list):
        for row in per_artifact:
            if not isinstance(row, dict):
                continue
            status = row.get("parser_status")
            artifact_type = row.get("artifact_type")
            if isinstance(status, str):
                status_counts[status] += 1
            if isinstance(artifact_type, str):
                artifact_type_counts[artifact_type] += 1
    return {
        "parser_status_counts": dict(sorted(status_counts.items())),
        "artifact_type_counts": dict(sorted(artifact_type_counts.items())),
        "normalized_events_written": payload.get("normalized_events_written"),
        "limitations": payload.get("limitations", []),
    }


def _events(output_dir: Path) -> list[dict[str, Any]]:
    payload = _read_json_object(output_dir / "normalized_events.json", "normalized_events")
    rows = payload.get("events", [])
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _event_family(row: Mapping[str, Any]) -> str:
    metadata = row.get("metadata", {})
    if isinstance(row.get("artifact_family"), str):
        return str(row["artifact_family"])
    if isinstance(metadata, dict) and isinstance(metadata.get("artifact_family"), str):
        return str(metadata["artifact_family"])
    if isinstance(row.get("artifact_type"), str):
        return str(row["artifact_type"])
    if isinstance(row.get("parser_name"), str):
        return str(row["parser_name"])
    return "unknown"


def _normalized_event_family_counts(output_dir: Path) -> dict[str, int]:
    counter: Counter[str] = Counter(_event_family(row) for row in _events(output_dir))
    return dict(sorted(counter.items()))


def _amcache_event_count(output_dir: Path) -> int:
    count = 0
    for row in _events(output_dir):
        artifact_type = str(row.get("artifact_type", "")).casefold()
        parser = str(row.get("parser_name", "")).casefold()
        event_type = str(row.get("event_type", "")).casefold()
        if artifact_type == "amcache" or parser == "amcacheparser" or "amcache" in event_type:
            count += 1
    return count


def _registry_user_activity_family_counts(output_dir: Path) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for row in _events(output_dir):
        family = _event_family(row).casefold()
        artifact_type = str(row.get("artifact_type", "")).casefold()
        if family in REGISTRY_USER_ACTIVITY_TYPES or artifact_type in REGISTRY_USER_ACTIVITY_TYPES:
            counter[artifact_type or family] += 1
    return dict(sorted(counter.items()))


def _not_assessed_questions(output_dir: Path) -> list[dict[str, object]]:
    payload = _read_json_object(output_dir / "case_questions.json", "case_questions")
    questions = payload.get("questions", [])
    if not isinstance(questions, list):
        return []
    rows: list[dict[str, object]] = []
    for question in questions:
        if not isinstance(question, dict) or question.get("status") != "not_assessed":
            continue
        rows.append(
            {
                "question_id": question.get("question_id"),
                "question": question.get("question"),
                "reason": question.get("reason"),
                "gaps": question.get("gaps", []),
            }
        )
    return rows


def _self_correction_events(output_dir: Path) -> list[dict[str, Any]]:
    payload = _read_json_object(
        output_dir / "self_correction_events.json",
        "self_correction_events",
    )
    rows = payload.get("events", [])
    if not isinstance(rows, list):
        return []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _traceability_files(output_dir: Path) -> dict[str, str | None]:
    paths = {
        "report": output_dir / "report.md",
        "audit": output_dir / "audit.jsonl",
        "decision_trace": output_dir / "decision_trace.json",
        "gap_analysis": output_dir / "gap_analysis.json",
        "self_correction_events": output_dir / "self_correction_events.json",
        "performance_summary": output_dir / "performance_summary.json",
        "findings": output_dir / "findings.json",
        "case_questions": output_dir / "case_questions.json",
        "normalized_events": output_dir / "normalized_events.json",
        "integrity_manifest": output_dir / INTEGRITY_MANIFEST_NAME,
        "progress": output_dir / "progress.jsonl",
    }
    trace_dir = output_dir / "openclaw-trace"
    if trace_dir.exists():
        for trace_file in sorted(trace_dir.glob("*")):
            if trace_file.is_file():
                trace_key = trace_file.name.replace(".", "_").replace("-", "_")
                paths[f"trace_{trace_key}"] = trace_file
    return {
        key: display_path(path) if path.exists() else None
        for key, path in paths.items()
    }


def _append_prepare_progress(
    progress_path: Path,
    *,
    case_id: str,
    status: str,
    message: str,
) -> None:
    try:
        append_progress_event(
            progress_path,
            case_id=case_id,
            phase="prepare_case",
            status=status,
            message=message,
        )
    except (OSError, ValueError):
        return


def prepare_case(
    request: Mapping[str, object],
    *,
    command_runner: CommandRunner = _default_command_runner,
) -> dict[str, object]:
    source_root_text = _optional_string(request, "source_root")
    source_manifest_text = _optional_string(request, "source_manifest")
    if bool(source_root_text) == bool(source_manifest_text):
        raise ValueError("exactly one of source_root or source_manifest is required")

    forbidden_roots: list[Path] = []
    source_root: Path | None = None
    source_manifest: Path | None = None
    if source_root_text is not None:
        source_root = resolve_user_path(source_root_text, "source_root")
        forbidden_roots.append(source_root)
    if source_manifest_text is not None:
        source_manifest = resolve_user_path(source_manifest_text, "source_manifest")
        require_json_path(source_manifest, "source_manifest")
        if source_manifest.exists():
            forbidden_roots.extend(evidence_roots_from_source_manifest(source_manifest))
    case_id = _case_id_from_request_or_generated(
        request,
        source_root=source_root,
        source_manifest=source_manifest,
    )

    source_manifest_out_text = _optional_string(request, "source_manifest_out")
    source_manifest_out: Path | None = None
    if source_manifest_out_text is not None:
        if source_root is None:
            raise ValueError("source_manifest_out is allowed only with source_root")
        source_manifest_out = validate_source_manifest_out(
            source_manifest_out_text,
            forbidden_roots=forbidden_roots,
        )

    output_dir = validate_integration_output_dir(
        _required_string(request, "output_dir"),
        forbidden_roots=forbidden_roots,
    )
    timeout_seconds = get_prepare_case_timeout_seconds(
        explicit=_optional_timeout_int(request, "timeout_seconds"),
    )
    argv = [
        sys.executable,
        "-m",
        "elenchos",
        "case",
        "prepare",
        "--case-id",
        case_id,
        "--output-dir",
        str(output_dir),
    ]
    if source_root is not None:
        argv.extend(["--source-root", str(source_root)])
    if source_manifest is not None:
        argv.extend(["--source-manifest", str(source_manifest)])
    if source_manifest_out is not None:
        argv.extend(["--source-manifest-out", str(source_manifest_out)])

    progress_path = progress_path_for_output_dir(output_dir)
    _append_prepare_progress(
        progress_path,
        case_id=case_id,
        status="started",
        message="prepare_case started",
    )
    started = time.monotonic()
    try:
        completed = command_runner(argv, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        duration_ms = round((time.monotonic() - started) * 1000)
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        timeout_label = str(timeout_seconds) if timeout_seconds is not None else "disabled"
        stderr = exc.stderr if isinstance(exc.stderr, str) else f"timeout after {timeout_label}s"
        stdout_path, stderr_path = _write_trace(
            output_dir=output_dir,
            operation_name="prepare_case",
            stdout=stdout,
            stderr=stderr,
        )
        _append_prepare_progress(
            progress_path,
            case_id=case_id,
            status="failed",
            message="prepare_case timed out",
        )
        return {
            "status": "failed",
            "command_name": "elenchos case prepare",
            "case_id": case_id,
            "output_dir": display_path(output_dir),
            "duration_ms": duration_ms,
            "trace_stdout": display_path(stdout_path),
            "trace_stderr": display_path(stderr_path),
            "error": f"prepare_case timed out after {timeout_label}s",
        }
    duration_ms = round((time.monotonic() - started) * 1000)
    stdout_path, stderr_path = _write_trace(
        output_dir=output_dir,
        operation_name="prepare_case",
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    parsed = _parse_key_value_stdout(completed.stdout)
    case_prep = _path_from_stdout_or_default(parsed, "case_prep", output_dir / "case_prep.json")
    source_manifest_result = _path_from_stdout_or_default(
        parsed,
        "source_manifest",
        output_dir / "source_manifest.json",
    )
    extraction_audit = _path_from_stdout_or_default(
        parsed,
        "extraction_audit",
        output_dir / "extraction_audit.jsonl",
    )
    status = "failed" if completed.returncode else parsed.get("status", "completed")
    _append_prepare_progress(
        progress_path,
        case_id=case_id,
        status="completed" if completed.returncode == 0 else "failed",
        message="prepare_case completed"
        if completed.returncode == 0
        else "prepare_case failed",
    )
    result: dict[str, object] = {
        "status": status,
        "command_name": "elenchos case prepare",
        "case_id": case_id,
        "output_dir": display_path(output_dir),
        "case_prep": display_path(case_prep),
        "prepared_manifest_path": display_path(case_prep),
        "source_manifest": display_path(source_manifest_result),
        "extraction_audit": display_path(extraction_audit),
        "prepared_artifact_count": _safe_int(parsed.get("prepared_artifacts")),
        "coverage_gap_count": _safe_int(parsed.get("coverage_gaps")),
        "duration_ms": duration_ms,
        "trace_stdout": display_path(stdout_path),
        "trace_stderr": display_path(stderr_path),
    }
    if completed.returncode != 0:
        result["error"] = _error_summary(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    return result


def run_case(
    request: Mapping[str, object],
    *,
    command_runner: CommandRunner = _default_command_runner,
) -> dict[str, object]:
    output_dir_text = _required_string(request, "output_dir")
    manifest_text = _optional_string(request, "prepared_manifest_path")
    if manifest_text is None:
        manifest_text = _optional_string(request, "artifact_manifest")
    if manifest_text is None:
        artifact_manifest = resolve_prepared_manifest_path(
            output_dir=resolve_user_path(output_dir_text, "output_dir"),
        )
    else:
        artifact_manifest = resolve_prepared_manifest_path(
            output_dir=resolve_user_path(output_dir_text, "output_dir"),
            explicit_path=manifest_text,
        )
    require_json_path(artifact_manifest, "artifact_manifest")
    case_id = _case_id_from_request_or_manifest(request, artifact_manifest)
    forbidden_roots: list[Path] = []
    if artifact_manifest.exists():
        forbidden_roots.extend(evidence_roots_from_case_prep(artifact_manifest))

    output_dir = validate_integration_output_dir(
        output_dir_text,
        forbidden_roots=forbidden_roots,
    )
    casebook_text = _optional_string(request, "casebook")
    casebook: Path | None = None
    if casebook_text is not None:
        casebook = resolve_user_path(casebook_text, "casebook")
        require_json_path(casebook, "casebook")

    max_iterations = _positive_int(request, "max_iterations", DEFAULT_MAX_ITERATIONS)
    max_normalized_events = _positive_int(
        request,
        "max_normalized_events",
        DEFAULT_MAX_NORMALIZED_EVENTS,
    )
    timeout_seconds = _positive_int(
        request,
        "timeout_seconds",
        DEFAULT_RUN_CASE_TIMEOUT_SECONDS,
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
    if casebook is not None:
        argv.extend(["--casebook", str(casebook)])

    started = time.monotonic()
    try:
        completed = command_runner(argv, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        duration_ms = round((time.monotonic() - started) * 1000)
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else f"timeout after {timeout_seconds}s"
        stdout_path, stderr_path = _write_trace(
            output_dir=output_dir,
            operation_name="run_case",
            stdout=stdout,
            stderr=stderr,
        )
        return {
            "status": "failed",
            "command_name": "elenchos agent run-case",
            "case_id": case_id,
            "output_dir": display_path(output_dir),
            "duration_ms": duration_ms,
            "trace_stdout": display_path(stdout_path),
            "trace_stderr": display_path(stderr_path),
            "error": f"run_case timed out after {timeout_seconds}s",
        }
    duration_ms = round((time.monotonic() - started) * 1000)
    stdout_path, stderr_path = _write_trace(
        output_dir=output_dir,
        operation_name="run_case",
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    parsed = _parse_key_value_stdout(completed.stdout)
    status = "failed" if completed.returncode else parsed.get("status", "completed")
    report_path = output_dir / "report.md"
    findings_path = output_dir / "findings.json"
    audit_path = _path_from_stdout_or_default(parsed, "audit", output_dir / "audit.jsonl")
    decision_trace_path = _path_from_stdout_or_default(
        parsed,
        "decision_trace",
        output_dir / "decision_trace.json",
    )
    case_questions_path = _path_from_stdout_or_default(
        parsed,
        "case_questions",
        output_dir / "case_questions.json",
    )
    gap_analysis_path = _path_from_stdout_or_default(
        parsed,
        "gap_analysis",
        output_dir / "gap_analysis.json",
    )
    self_correction_events_path = _path_from_stdout_or_default(
        parsed,
        "self_correction_events",
        output_dir / "self_correction_events.json",
    )
    performance_summary_path = _path_from_stdout_or_default(
        parsed,
        "performance_summary",
        output_dir / "performance_summary.json",
    )
    integrity_manifest_file = output_dir / INTEGRITY_MANIFEST_NAME
    integrity_manifest_path: Path | None = (
        integrity_manifest_file if integrity_manifest_file.is_file() else None
    )
    result: dict[str, object] = {
        "status": status,
        "command_name": "elenchos agent run-case",
        "case_id": case_id,
        "output_dir": display_path(output_dir),
        "report": display_path(report_path) if report_path.exists() else None,
        "findings": display_path(findings_path) if findings_path.exists() else None,
        "audit": display_path(audit_path),
        "decision_trace": display_path(decision_trace_path),
        "case_questions": display_path(case_questions_path),
        "gap_analysis": display_path(gap_analysis_path),
        "self_correction_events": display_path(self_correction_events_path),
        "performance_summary": display_path(performance_summary_path),
        "integrity_manifest": display_path(integrity_manifest_path),
        "finding_status_counts": _findings_status_counts(output_dir),
        "case_question_status_counts": _case_question_status_counts(output_dir),
        "parser_status_summary": _parser_status_summary(output_dir),
        "duration_ms": duration_ms,
        "trace_stdout": display_path(stdout_path),
        "trace_stderr": display_path(stderr_path),
    }
    if completed.returncode != 0:
        result["error"] = _error_summary(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    return result


def summarize_run(request: Mapping[str, object]) -> dict[str, object]:
    output_dir = validate_generated_read_dir(_required_string(request, "output_dir"))
    status = "completed" if output_dir.exists() else "failed"
    progress_path = progress_path_for_output_dir(output_dir)
    if output_dir.exists():
        append_progress_event(
            progress_path,
            case_id=_summary_case_id(output_dir),
            phase="summarize_run",
            status=status,
            message="summarize_run completed",
        )
    coverage = _read_json_object(output_dir / "coverage_summary.json", "coverage_summary")
    limitations = coverage.get("limitations", [])
    if not isinstance(limitations, list):
        limitations = []
    return {
        "status": status,
        "output_dir": display_path(output_dir),
        "report": display_path(output_dir / "report.md")
        if (output_dir / "report.md").exists()
        else None,
        "finding_status_counts": _findings_status_counts(output_dir),
        "case_question_status_counts": _case_question_status_counts(output_dir),
        "parser_coverage_summary": _parser_status_summary(output_dir),
        "normalized_event_family_counts": _normalized_event_family_counts(output_dir),
        "amcache_event_count": _amcache_event_count(output_dir),
        "registry_user_activity_family_counts": _registry_user_activity_family_counts(output_dir),
        "unsupported_not_assessed_areas": _not_assessed_questions(output_dir),
        "real_gap_self_correction_events": _self_correction_events(output_dir),
        "progress_trace": display_path(progress_path) if progress_path.exists() else None,
        "progress_event_count": len(read_progress_events(progress_path)),
        "required_trace_files": _traceability_files(output_dir),
        "limitations": limitations,
    }


def _summary_case_id(output_dir: Path) -> str:
    for filename, label in (
        ("agent_run.json", "agent_run"),
        ("coverage_summary.json", "coverage_summary"),
        ("findings.json", "findings"),
    ):
        payload = _read_json_object(output_dir / filename, label)
        case_id = payload.get("case_id")
        if isinstance(case_id, str) and case_id:
            return case_id
    return output_dir.parent.name or "unknown"


def _forbidden_wording_hits(report_path: Path) -> list[dict[str, object]]:
    if not report_path.exists():
        return []
    hits: list[dict[str, object]] = []
    for line_number, line in enumerate(report_path.read_text(encoding="utf-8").splitlines(), 1):
        lowered = line.casefold()
        for phrase in FORBIDDEN_REPORT_PHRASES:
            if phrase in lowered:
                hits.append({"line": line_number, "phrase": phrase})
    return hits


def _unsupported_question_violations(case_questions_path: Path) -> list[dict[str, object]]:
    if not case_questions_path.exists():
        return []
    payload = _read_json_object(case_questions_path, "case_questions")
    questions = payload.get("questions", [])
    if not isinstance(questions, list):
        return [{"question_id": None, "reason": "case_questions.questions is not a list"}]
    violations: list[dict[str, object]] = []
    for question in questions:
        if not isinstance(question, dict):
            continue
        question_id = question.get("question_id")
        if question.get("direct_support_schema") is True:
            continue
        status = question.get("status")
        supported_by_scope = question.get("supported_by_current_scope")
        linked_refs = question.get("linked_evidence_refs", [])
        is_scope_unsupported = supported_by_scope is False
        is_not_assessed = status == "not_assessed"
        if not is_scope_unsupported and not is_not_assessed:
            continue
        if is_scope_unsupported and status != "not_assessed":
            violations.append(
                {
                    "question_id": question_id,
                    "reason": "scope-unsupported question must remain not_assessed",
                    "status": status,
                }
            )
        if isinstance(linked_refs, list) and linked_refs:
            violations.append(
                {
                    "question_id": question_id,
                    "reason": "unsupported question carries linked evidence refs",
                    "linked_evidence_ref_count": len(linked_refs),
                }
            )
    return violations


def validate_run_outputs(request: Mapping[str, object]) -> dict[str, object]:
    output_dir = validate_generated_read_dir(_required_string(request, "output_dir"))
    missing_files = [
        filename
        for filename in REQUIRED_RUN_OUTPUTS
        if not (output_dir / filename).is_file()
    ]
    integrity_violations = validate_integrity_manifest(output_dir)
    report_path = output_dir / "report.md"
    forbidden_hits = _forbidden_wording_hits(report_path)
    unsupported_violations = _unsupported_question_violations(output_dir / "case_questions.json")
    self_correction_events = _self_correction_events(output_dir)
    report_line_count = (
        len(report_path.read_text(encoding="utf-8").splitlines())
        if report_path.exists()
        else 0
    )
    validation_status = (
        "pass"
        if (
            not missing_files
            and not forbidden_hits
            and not unsupported_violations
            and not integrity_violations
        )
        else "fail"
    )
    progress_path = progress_path_for_output_dir(output_dir)
    if output_dir.exists():
        append_progress_event(
            progress_path,
            case_id=_summary_case_id(output_dir),
            phase="validate_run_outputs",
            status="completed" if validation_status == "pass" else "failed",
            message=f"validate_run_outputs {validation_status}",
        )
    notes: list[str] = []
    if validation_status == "pass":
        notes.append("required generated outputs are present and report wording is bounded")
        notes.append("run integrity manifest hashes verified")
        notes.append("scope-unsupported and not_assessed question safety checked")
    for event in self_correction_events:
        final_wording = event.get("final_wording")
        if isinstance(final_wording, str) and final_wording:
            notes.append(final_wording)
    result: dict[str, object] = {
        "validation_status": validation_status,
        "output_dir": display_path(output_dir),
        "missing_files": missing_files,
        "integrity_violations": integrity_violations,
        "forbidden_wording_hits": forbidden_hits,
        "unsupported_question_violations": unsupported_violations,
        "self_correction_event_count": len(self_correction_events),
        "report_line_count": report_line_count,
        "progress_trace": display_path(progress_path) if progress_path.exists() else None,
        "progress_event_count": len(read_progress_events(progress_path)),
        "traceability_files": _traceability_files(output_dir),
        "notes": notes,
    }
    result["claim_boundary_required"] = bool(self_correction_events)
    if output_dir.exists():
        (output_dir / "validation_summary.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return result


RationaleClaimPhrase = tuple[str, ...]


UNSUPPORTED_FINAL_CLAIM_PHRASES: RationaleClaimPhrase = (
    "confirmed compromise",
    "confirmed theft",
    "confirmed exfiltration",
    "confirmed malware",
    "confirmed memory finding",
    "confirmed attribution",
    "proved compromise",
    "proved theft",
    "proved exfiltration",
)


def _reject_unsafe_rationale_text(*parts: str) -> None:
    text = " ".join(parts).casefold()
    for phrase in UNSUPPORTED_FINAL_CLAIM_PHRASES:
        if phrase in text:
            raise ValueError(
                "model rationale must not include unsupported final forensic claims"
            )


def inspect_run_state(request: Mapping[str, object]) -> dict[str, object]:
    output_dir = validate_generated_read_dir(_required_string(request, "output_dir"))
    summary = inspect_generated_run_state(output_dir)
    payload = summary.to_dict()
    payload["status"] = "completed"
    return payload


def record_model_rationale(request: Mapping[str, object]) -> dict[str, object]:
    output_dir = validate_generated_read_dir(_required_string(request, "output_dir"))
    agent_run_dir = agent_run_dir_from_output_dir(output_dir)
    path = model_rationale_path(agent_run_dir)
    visible_message = _required_string(request, "visible_message")
    rationale_summary = _required_string(request, "rationale_summary")
    proposed_action = _required_string(request, "proposed_action")
    _reject_unsafe_rationale_text(visible_message, rationale_summary)
    record = ModelRationaleRecord(
        rationale_id=next_sequence_id("rationale", path),
        timestamp_utc=utc_now(),
        phase=_required_string(request, "phase"),
        visible_message=visible_message,
        proposed_action=proposed_action,
        rationale_summary=rationale_summary,
        basis_files=_string_list_request(request, "basis_files"),
        observed_state=_optional_object_request(request, "observed_state"),
        forbidden_claims_avoided=_optional_string_list_request(
            request,
            "forbidden_claims_avoided",
        ),
        confidence=_required_string(request, "confidence"),
    )
    append_jsonl(path, record.to_dict())
    append_orchestration_event(
        agent_run_dir,
        event_type="model_rationale",
        payload={
            "rationale_id": record.rationale_id,
            "proposed_action": record.proposed_action,
            "phase": record.phase,
        },
    )
    return {
        "status": "completed",
        "record": record.to_dict(),
        "rationale_id": record.rationale_id,
        "model_rationale_path": display_path(path),
        "output_dir": display_path(agent_run_dir),
    }


def evaluate_action_policy(request: Mapping[str, object]) -> dict[str, object]:
    output_dir = validate_generated_read_dir(_required_string(request, "output_dir"))
    return evaluate_policy(
        output_dir=output_dir,
        proposed_action=_required_string(request, "proposed_action"),
        action_args=_optional_object_request(request, "action_args"),
        rationale_id=_optional_string(request, "rationale_id"),
    )


def _self_policy_gate(name: str, request: Mapping[str, object]) -> dict[str, object] | None:
    if name not in SELF_POLICY_GATED_TOOLS:
        return None
    output_dir = resolve_user_path(_required_string(request, "output_dir"), "output_dir")
    decision = evaluate_policy(
        output_dir=output_dir,
        proposed_action=name,
        action_args=dict(request),
        rationale_id=_optional_string(request, "rationale_id"),
    )
    if decision["decision"] != "allowed":
        raise ValueError(f"{name} rejected by policy: {decision['reason']}")
    return decision


def _attach_policy(
    result: dict[str, object],
    policy: dict[str, object] | None,
) -> dict[str, object]:
    if policy is None:
        return result
    result["policy_decision"] = policy.get("policy_decision")
    result["policy_decisions_path"] = policy.get("policy_decisions_path")
    result["visible_policy_message"] = policy.get("visible_policy_message")
    return result


def start_case_run(request: Mapping[str, object]) -> dict[str, object]:
    return start_case_run_job(request)


def poll_case_run(request: Mapping[str, object]) -> dict[str, object]:
    return poll_case_run_job(request)


def finish_case_run(request: Mapping[str, object]) -> dict[str, object]:
    return finish_case_run_job(request)


def emit_claim_boundary(request: Mapping[str, object]) -> dict[str, object]:
    output_dir = validate_generated_read_dir(_required_string(request, "output_dir"))
    agent_run_dir = agent_run_dir_from_output_dir(output_dir)
    records = _claim_boundary_records(agent_run_dir)
    if records:
        wording = [
            {
                "final_wording": row.get("final_wording"),
                "scope_boundary": row.get("scope_boundary"),
                "recommended_next_artifacts": row.get("recommended_next_artifacts", []),
                "source": row.get("source"),
            }
            for row in records
        ]
    else:
        wording = [
            {
                "final_wording": (
                    "Elenchos did not find sufficient support for a confirmed theft, "
                    "exfiltration, memory, malware, attribution, or final compromise "
                    "conclusion within the submitted artifact scope. Analyst review "
                    "and additional artifacts remain required."
                ),
                "scope_boundary": (
                    "Current generated outputs do not provide deterministic support "
                    "for those final conclusions."
                ),
                "recommended_next_artifacts": [],
                "source": "conservative_fallback",
            }
        ]
    return {
        "status": "completed",
        "output_dir": display_path(agent_run_dir),
        "claim_boundaries": wording,
        "status_upgrade_performed": False,
    }


def _claim_boundary_records(agent_run_dir: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for filename, source_key in (
        ("self_correction_events.json", "self_correction_events"),
        ("gap_analysis.json", "gap_analysis"),
        ("case_questions.json", "case_questions"),
    ):
        payload = _read_json_object(agent_run_dir / filename, filename)
        candidates: list[object] = []
        if filename == "self_correction_events.json":
            raw = payload.get("events", [])
            candidates = raw if isinstance(raw, list) else []
        elif filename == "gap_analysis.json":
            raw = payload.get("claim_boundaries", [])
            candidates = raw if isinstance(raw, list) else []
        else:
            raw = payload.get("claim_boundaries", [])
            candidates = raw if isinstance(raw, list) else []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            final_wording = candidate.get("final_wording")
            scope_boundary = candidate.get("scope_boundary")
            if isinstance(final_wording, str) and final_wording:
                record = dict(candidate)
                record["source"] = source_key
                if not isinstance(scope_boundary, str):
                    record["scope_boundary"] = None
                rows.append(record)
    return rows


def dispatch_tool(
    name: str,
    request: Mapping[str, object],
    *,
    command_runner: CommandRunner = _default_command_runner,
) -> dict[str, object]:
    policy = _self_policy_gate(name, request)
    if name == "prepare_case":
        return _attach_policy(prepare_case(request, command_runner=command_runner), policy)
    if name == "run_case":
        return _attach_policy(run_case(request, command_runner=command_runner), policy)
    if name == "summarize_run":
        return _attach_policy(summarize_run(request), policy)
    if name == "validate_run_outputs":
        return _attach_policy(validate_run_outputs(request), policy)
    if name == "inspect_run_state":
        return _attach_policy(inspect_run_state(request), policy)
    if name == "record_model_rationale":
        return record_model_rationale(request)
    if name == "evaluate_action_policy":
        return evaluate_action_policy(request)
    if name == "start_case_run":
        return _attach_policy(start_case_run(request), policy)
    if name == "poll_case_run":
        return _attach_policy(poll_case_run(request), policy)
    if name == "finish_case_run":
        return _attach_policy(finish_case_run(request), policy)
    if name == "emit_claim_boundary":
        return _attach_policy(emit_claim_boundary(request), policy)
    raise ValueError(f"unknown Elenchos integration operation: {name}")


def _load_json_input(value: str | None) -> dict[str, object]:
    if value is None or value == "-":
        raw = sys.stdin.read()
    elif value.startswith("@"):
        raw = Path(value[1:]).read_text(encoding="utf-8")
    else:
        raw = value
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("JSON input must be an object")
    return payload


def _emit_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _copy_trace_for_smoke(result: Mapping[str, object], trace_dir: Path, operation: str) -> None:
    trace_dir.mkdir(parents=True, exist_ok=True)
    for stream in ("stdout", "stderr"):
        key = f"trace_{stream}"
        value = result.get(key)
        if not isinstance(value, str):
            continue
        source = repo_root() / value
        if source.exists():
            shutil.copyfile(source, trace_dir / f"{operation}.{stream}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m elenchos.integrations.tool_adapter",
        description="Bounded Elenchos OpenClaw/MCP-compatible tool adapter",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("manifest", help="Print JSON tool manifest")
    for command in (
        "prepare-case",
        "run-case",
        "summarize-run",
        "validate-run-outputs",
        "inspect-run-state",
        "record-model-rationale",
        "evaluate-action-policy",
        "start-case-run",
        "poll-case-run",
        "finish-case-run",
        "emit-claim-boundary",
    ):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument(
            "--json-input",
            help="JSON object string, @path, or '-' for stdin.",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "manifest":
            _emit_json({"tools": get_tool_definitions()})
            return 0
        command_to_tool = {
            "prepare-case": "prepare_case",
            "run-case": "run_case",
            "summarize-run": "summarize_run",
            "validate-run-outputs": "validate_run_outputs",
            "inspect-run-state": "inspect_run_state",
            "record-model-rationale": "record_model_rationale",
            "evaluate-action-policy": "evaluate_action_policy",
            "start-case-run": "start_case_run",
            "poll-case-run": "poll_case_run",
            "finish-case-run": "finish_case_run",
            "emit-claim-boundary": "emit_claim_boundary",
        }
        if args.command in command_to_tool:
            request = _load_json_input(args.json_input)
            _emit_json(dispatch_tool(command_to_tool[args.command], request))
            return 0
        parser.print_help()
        return 1
    except Exception as exc:
        _emit_json(_error_payload(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
