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
from pathlib import Path
from typing import Any

from siftguard.integrations.safe_paths import (
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
from siftguard.parser.paths import validate_parser_path_identifier
from siftguard.policy.paths import is_generated_output_path, is_relative_to
from siftguard.progress import (
    append_progress_event,
    progress_path_for_output_dir,
    read_progress_events,
)
from siftguard.triage import SUPPORTED_EVENT_SELECTION_PROFILES

DEFAULT_PREPARE_TIMEOUT_SECONDS = 900
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

CommandRunner = Callable[[list[str], int], subprocess.CompletedProcess[str]]


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


def _path_output_schema() -> dict[str, object]:
    return {"anyOf": [{"type": "string"}, {"type": "null"}]}


TOOL_DEFINITIONS: dict[str, dict[str, object]] = {
    "prepare_case": {
        "name": "prepare_case",
        "title": "Prepare Case",
        "description": (
            "Prepare supported SIFTGuard case artifacts from a source root or JSON source "
            "manifest. This tool invokes the deterministic CLI with typed arguments and "
            "never passes raw evidence contents to a model."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "case_id": _string_schema("Case identifier."),
                "source_root": _optional_string_schema(
                    "Source root to discover; mutually exclusive with source_manifest."
                ),
                "source_manifest": _optional_string_schema(
                    "Existing SIFTGuard JSON source manifest."
                ),
                "output_dir": _string_schema("Generated case-prep output directory."),
                "source_manifest_out": _optional_string_schema(
                    "Optional JSON source manifest output path for source-root mode."
                ),
                "timeout_seconds": _integer_schema(
                    "Maximum prepare runtime in seconds.",
                    DEFAULT_PREPARE_TIMEOUT_SECONDS,
                ),
            },
            "required": ["case_id", "output_dir"],
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
            "Run SIFTGuard's deterministic agent run-case workflow from a prepared "
            "case manifest. The model can request this bounded tool, but SIFTGuard "
            "computes evidence-backed outputs."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "case_id": _string_schema("Case identifier."),
                "artifact_manifest": _string_schema("Path to case_prep.json."),
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
            "required": ["case_id", "artifact_manifest", "output_dir"],
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
            "Read generated SIFTGuard JSON/report outputs only and return a concise "
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
            "Validate required generated SIFTGuard outputs, report wording, and "
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
}


def get_tool_definitions() -> list[dict[str, object]]:
    return [TOOL_DEFINITIONS[name] for name in sorted(TOOL_DEFINITIONS)]


def _default_command_runner(
    argv: list[str],
    timeout_seconds: int,
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


def prepare_case(
    request: Mapping[str, object],
    *,
    command_runner: CommandRunner = _default_command_runner,
) -> dict[str, object]:
    case_id = validate_parser_path_identifier(_required_string(request, "case_id"), "case_id")
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
    timeout_seconds = _positive_int(
        request,
        "timeout_seconds",
        DEFAULT_PREPARE_TIMEOUT_SECONDS,
    )
    argv = [
        sys.executable,
        "-m",
        "siftguard",
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

    started = time.monotonic()
    try:
        completed = command_runner(argv, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        duration_ms = round((time.monotonic() - started) * 1000)
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else f"timeout after {timeout_seconds}s"
        stdout_path, stderr_path = _write_trace(
            output_dir=output_dir,
            operation_name="prepare_case",
            stdout=stdout,
            stderr=stderr,
        )
        return {
            "status": "failed",
            "command_name": "siftguard case prepare",
            "case_id": case_id,
            "output_dir": display_path(output_dir),
            "duration_ms": duration_ms,
            "trace_stdout": display_path(stdout_path),
            "trace_stderr": display_path(stderr_path),
            "error": f"prepare_case timed out after {timeout_seconds}s",
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
    result: dict[str, object] = {
        "status": status,
        "command_name": "siftguard case prepare",
        "case_id": case_id,
        "output_dir": display_path(output_dir),
        "case_prep": display_path(case_prep),
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
    case_id = validate_parser_path_identifier(_required_string(request, "case_id"), "case_id")
    artifact_manifest = resolve_user_path(
        _required_string(request, "artifact_manifest"),
        "artifact_manifest",
    )
    require_json_path(artifact_manifest, "artifact_manifest")
    forbidden_roots: list[Path] = []
    if artifact_manifest.exists():
        forbidden_roots.extend(evidence_roots_from_case_prep(artifact_manifest))

    output_dir = validate_integration_output_dir(
        _required_string(request, "output_dir"),
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
        "siftguard",
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
            "command_name": "siftguard agent run-case",
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
    result: dict[str, object] = {
        "status": status,
        "command_name": "siftguard agent run-case",
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
        if not missing_files and not forbidden_hits and not unsupported_violations
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
        notes.append("scope-unsupported and not_assessed question safety checked")
    for event in self_correction_events:
        final_wording = event.get("final_wording")
        if isinstance(final_wording, str) and final_wording:
            notes.append(final_wording)
    return {
        "validation_status": validation_status,
        "output_dir": display_path(output_dir),
        "missing_files": missing_files,
        "forbidden_wording_hits": forbidden_hits,
        "unsupported_question_violations": unsupported_violations,
        "self_correction_event_count": len(self_correction_events),
        "report_line_count": report_line_count,
        "progress_trace": display_path(progress_path) if progress_path.exists() else None,
        "progress_event_count": len(read_progress_events(progress_path)),
        "traceability_files": _traceability_files(output_dir),
        "notes": notes,
    }


def dispatch_tool(
    name: str,
    request: Mapping[str, object],
    *,
    command_runner: CommandRunner = _default_command_runner,
) -> dict[str, object]:
    if name == "prepare_case":
        return prepare_case(request, command_runner=command_runner)
    if name == "run_case":
        return run_case(request, command_runner=command_runner)
    if name == "summarize_run":
        return summarize_run(request)
    if name == "validate_run_outputs":
        return validate_run_outputs(request)
    raise ValueError(f"unknown SIFTGuard integration operation: {name}")


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
        prog="python -m siftguard.integrations.tool_adapter",
        description="Bounded SIFTGuard OpenClaw/MCP-compatible tool adapter",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("manifest", help="Print JSON tool manifest")
    for command in (
        "prepare-case",
        "run-case",
        "summarize-run",
        "validate-run-outputs",
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
