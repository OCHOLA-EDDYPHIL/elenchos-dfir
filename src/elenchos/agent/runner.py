from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from elenchos.agent.audit import append_agent_audit_event, record_agent_step_event
from elenchos.agent.models import (
    AgentArtifactRef,
    AgentPhase,
    AgentRun,
    AgentRunStatus,
    AgentState,
    AgentStep,
    AgentStepStatus,
)
from elenchos.agent.planner import AGENT_PHASES, build_default_agent_plan
from elenchos.agent.self_correction import (
    apply_self_correction,
    record_max_iterations_correction,
)
from elenchos.agent.verifier import (
    VerificationFailure,
    VerificationResult,
    VerificationStatus,
    verify_agent_outputs,
)
from elenchos.audit.execution_ledger import utc_now
from elenchos.correlation.models import SubjectTimeline
from elenchos.correlation.timeline import build_subject_timelines
from elenchos.evidence.manifest import EvidenceArtifact, EvidenceManifest, read_manifest
from elenchos.parser.amcache import normalize_amcache_csv, parse_amcache_artifact
from elenchos.parser.mft import (
    normalize_mftecmd_csv,
    parse_mft_artifact,
    parse_mft_artifact_for_triage,
    select_mftecmd_csv_for_triage,
)
from elenchos.parser.registry_runkeys import (
    normalize_recmd_runkeys_csv,
    parse_registry_runkeys_artifact,
)
from elenchos.parser.registry_user_activity import (
    normalize_recmd_user_activity_csv,
    parse_registry_user_activity_artifact,
)
from elenchos.parser.result import ParserResult
from elenchos.policy.paths import is_relative_to
from elenchos.progress import (
    ProgressEvent,
    append_progress_event,
    progress_display_rows,
    read_progress_events,
)
from elenchos.reporting.markdown_report import render_markdown_report
from elenchos.triage import (
    CASE_WINDOW,
    EVENT_SELECTION_FIRST_N,
    EVENT_SELECTION_FORENSIC_TRIAGE,
    TriageAnchors,
    empty_selection_counts,
    validate_event_selection_profile,
)
from elenchos.validation.claims import (
    ClaimValidationResult,
    candidates_from_subject_timelines,
    validate_claim_candidates,
)
from elenchos.validation.models import Finding
from elenchos.workflows.correlation import load_normalized_timeline_events

Clock = Callable[[], str]

GENERATED_OUTPUT_PARTS = {"runs", "outputs", "analysis"}
PARSER_RESULT_ARTIFACT_TYPES = {"parser_result", "parser_result_json"}
NORMALIZED_EVENT_ARTIFACT_TYPES = {
    "normalized_events",
    "normalized_events_json",
    "parser_events_json",
}
SYNTHETIC_CSV_ARTIFACT_TYPES = {
    "mftecmd_csv",
    "recmd_runkeys_csv",
    "recmd_user_activity_csv",
    "amcacheparser_csv",
}
RAW_PARSER_ARTIFACT_TYPES = {"mft", "registry", "registry_hive", "amcache"}
SUPPORTED_PARSE_ARTIFACT_TYPES = (
    PARSER_RESULT_ARTIFACT_TYPES
    | NORMALIZED_EVENT_ARTIFACT_TYPES
    | SYNTHETIC_CSV_ARTIFACT_TYPES
    | RAW_PARSER_ARTIFACT_TYPES
)
BOUNDED_ARTIFACT_TYPE_PRIORITY = {
    "registry": 0,
    "registry_hive": 0,
    "recmd_runkeys_csv": 0,
    "recmd_user_activity_csv": 0,
    "amcache": 1,
    "amcacheparser_csv": 1,
    "mft": 2,
    "mftecmd_csv": 2,
}
EVENT_LIMIT_WARNING_MARKER = "max_events="
HIGH_VOLUME_MFT_ARTIFACT_TYPES = {"mft", "mftecmd_csv"}
PARSER_NAME_BY_ARTIFACT_TYPE = {
    "mft": "mftecmd",
    "mftecmd_csv": "mftecmd",
    "registry": "recmd",
    "registry_hive": "recmd",
    "recmd_runkeys_csv": "recmd",
    "recmd_user_activity_csv": "recmd",
    "amcache": "amcacheparser",
    "amcacheparser_csv": "amcacheparser",
}


@dataclass(slots=True)
class ArtifactRows:
    rows: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    parser_name: str | None = None
    parser_status: str = "success"
    source_rows_seen: int | None = None
    source_events_seen: int | None = None
    selection_counts: dict[str, int] = field(default_factory=empty_selection_counts)
    dropped_due_to_cap: int = 0
    bounded: bool = False
    skip_reason: str | None = None
    coverage_gaps: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class AgentWorkflowPaths:
    output_dir: Path
    normalized_events_path: Path
    coverage_summary_path: Path
    timelines_path: Path
    findings_path: Path
    report_path: Path
    audit_path: Path
    agent_run_path: Path
    progress_path: Path


@dataclass(slots=True)
class AgentWorkflowContext:
    case_id: str
    manifest_path: Path
    manifest: EvidenceManifest
    paths: AgentWorkflowPaths
    clock: Clock
    max_normalized_events: int | None = None
    event_selection_profile: str = EVENT_SELECTION_FIRST_N
    input_source: str | None = None
    fixture_id: str | None = None
    induced_findings: list[dict[str, Any]] = field(default_factory=list)
    induced_findings_applied: bool = False
    artifacts: list[AgentArtifactRef] = field(default_factory=list)
    normalized_event_rows: list[dict[str, Any]] = field(default_factory=list)
    timelines: list[SubjectTimeline] = field(default_factory=list)
    validation_results: list[ClaimValidationResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    normalized_event_limit_reached: bool = False
    artifact_event_counts: dict[str, int] = field(default_factory=dict)
    coverage_artifacts: list[dict[str, Any]] = field(default_factory=list)
    coverage_summary: dict[str, Any] = field(default_factory=dict)
    selection_counts: dict[str, int] = field(default_factory=empty_selection_counts)
    case_windows: tuple[CASE_WINDOW, ...] = ()


def _require_non_empty_string(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _validate_optional_positive_int(name: str, value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer when provided")
    return value


def _is_generated_output_path(path: Path) -> bool:
    parts = tuple(part.casefold() for part in path.parts)
    if any(part in GENERATED_OUTPUT_PARTS for part in parts):
        return True
    return any(
        left == "reports" and right == "generated"
        for left, right in zip(parts, parts[1:], strict=False)
    )


def _validate_manifest_path(manifest_path: Path) -> Path:
    resolved = manifest_path.resolve()
    if not resolved.exists():
        raise ValueError(f"manifest does not exist: {manifest_path}")
    if resolved.is_dir():
        raise ValueError(f"manifest path is a directory: {manifest_path}")
    return resolved


def _validate_output_dir(output_dir: Path, manifest: EvidenceManifest) -> Path:
    resolved = output_dir.resolve()
    cwd = Path.cwd().resolve()
    case_root = Path(manifest.case_root).resolve()

    if resolved == cwd:
        raise ValueError("output_dir must not be the repository root")
    if is_relative_to(resolved, case_root):
        raise ValueError("output_dir must not be inside the manifest case_root")
    if not _is_generated_output_path(resolved):
        raise ValueError(
            "output_dir must be under an ignored generated output path such as "
            "runs/, outputs/, analysis/, or reports/generated/"
        )
    return resolved


def _resolve_output_path(output_dir: Path, name: str) -> Path:
    path = (output_dir / name).resolve()
    if not is_relative_to(path, output_dir):
        raise ValueError(f"output path '{path}' must be under output_dir '{output_dir}'")
    return path


def _workflow_paths(output_dir: Path) -> AgentWorkflowPaths:
    return AgentWorkflowPaths(
        output_dir=output_dir,
        normalized_events_path=_resolve_output_path(output_dir, "normalized_events.json"),
        coverage_summary_path=_resolve_output_path(output_dir, "coverage_summary.json"),
        timelines_path=_resolve_output_path(output_dir, "subject_timelines.json"),
        findings_path=_resolve_output_path(output_dir, "findings.json"),
        report_path=_resolve_output_path(output_dir, "report.md"),
        audit_path=_resolve_output_path(output_dir, "audit.jsonl"),
        agent_run_path=_resolve_output_path(output_dir, "agent_run.json"),
        progress_path=_resolve_output_path(output_dir, "progress.jsonl"),
    )


def _clear_previous_agent_outputs(paths: AgentWorkflowPaths) -> None:
    for path in (
        paths.normalized_events_path,
        paths.coverage_summary_path,
        paths.timelines_path,
        paths.findings_path,
        paths.report_path,
        paths.audit_path,
        paths.agent_run_path,
        paths.progress_path,
    ):
        if path.exists():
            if path.is_dir():
                raise ValueError(f"expected agent output file path is a directory: {path}")
            path.unlink()


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON in {path.name}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return payload


FIXTURE_SCHEMA_VERSION = 1
SYNTHETIC_FIXTURE_INPUT_SOURCES = {
    "synthetic_positive_control",
    "synthetic_self_correction_control",
}
BLOCKED_FIXTURE_KEYS = {
    "argv",
    "bash",
    "cmd",
    "command",
    "executable",
    "powershell",
    "raw_command",
    "script",
    "shell",
    "subprocess",
}


@dataclass(frozen=True, slots=True)
class AgentFixtureSpec:
    fixture_id: str
    case_id: str
    input_source: str
    manifest_path: Path
    induced_findings: list[dict[str, Any]]


def _validate_fixture_json(name: str, value: Any) -> Any:
    if isinstance(value, dict):
        checked: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                raise ValueError(f"{name} contains an invalid key")
            if key.casefold() in BLOCKED_FIXTURE_KEYS:
                raise ValueError(f"{name} contains blocked execution key: {key}")
            checked[key] = _validate_fixture_json(f"{name}.{key}", child)
        return checked
    if isinstance(value, list):
        return [_validate_fixture_json(f"{name}[]", child) for child in value]
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    raise TypeError(f"{name} must contain only JSON-compatible values")


def _fixture_relative_path(*, fixture_path: Path, value: Any, field_name: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"fixture {field_name} must be a non-empty string")
    candidate = Path(value)
    if candidate.is_absolute():
        raise ValueError(f"fixture {field_name} must be relative")
    resolved = (fixture_path.parent / candidate).resolve()
    if not is_relative_to(resolved, fixture_path.parent.resolve()):
        raise ValueError(f"fixture {field_name} must stay under the fixture directory")
    if not resolved.exists() or resolved.is_dir():
        raise ValueError(f"fixture {field_name} does not exist: {value}")
    return resolved


def _string_list_from_fixture(value: Any, *, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"fixture finding {field_name} must be a list of strings")
    return list(value)


def _dict_list_from_fixture(value: Any, *, field_name: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"fixture finding {field_name} must be a list of objects")
    return [dict(item) for item in value]


def _normalize_induced_finding(row: dict[str, Any]) -> dict[str, Any]:
    finding_id = row.get("finding_id")
    claim = row.get("claim")
    status = row.get("status")
    confidence = row.get("confidence", "high")
    kind = row.get("kind", "conclusion")
    rationale = row.get(
        "rationale",
        "Synthetic control introduced an unsupported claim for verification.",
    )
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("induced finding requires finding_id")
    if not isinstance(claim, str) or not claim:
        raise ValueError("induced finding requires claim")
    if status not in {"confirmed", "inferred"}:
        raise ValueError("induced finding status must be confirmed or inferred")
    if confidence not in {"low", "medium", "high"}:
        raise ValueError("induced finding confidence must be low, medium, or high")
    if kind not in {"observation", "conclusion"}:
        raise ValueError("induced finding kind must be observation or conclusion")
    if not isinstance(rationale, str) or not rationale:
        raise ValueError("induced finding rationale must be a non-empty string")

    return {
        "finding_id": finding_id,
        "claim": claim,
        "status": status,
        "confidence": confidence,
        "kind": kind,
        "evidence_refs": _dict_list_from_fixture(
            row.get("evidence_refs"),
            field_name="evidence_refs",
        ),
        "audit_event_refs": _string_list_from_fixture(
            row.get("audit_event_refs"),
            field_name="audit_event_refs",
        ),
        "artifact_hashes": _string_list_from_fixture(
            row.get("artifact_hashes"),
            field_name="artifact_hashes",
        ),
        "raw_record_refs": _string_list_from_fixture(
            row.get("raw_record_refs"),
            field_name="raw_record_refs",
        ),
        "rationale": rationale,
        "limitations": _string_list_from_fixture(
            row.get("limitations"),
            field_name="limitations",
        ),
        "supports_final_report": False,
    }


def load_agent_fixture_spec(fixture_path: Path, *, case_id: str) -> AgentFixtureSpec:
    resolved_fixture = _validate_manifest_path(fixture_path)
    payload = _validate_fixture_json("fixture", _load_json_object(resolved_fixture))
    schema_version = payload.get("schema_version")
    if schema_version != FIXTURE_SCHEMA_VERSION:
        raise ValueError(f"unsupported fixture schema_version: {schema_version}")

    fixture_id = payload.get("fixture_id")
    fixture_case_id = payload.get("case_id")
    input_source = payload.get("input_source")
    if not isinstance(fixture_id, str) or not fixture_id:
        raise ValueError("fixture_id must be a non-empty string")
    if fixture_case_id != case_id:
        raise ValueError(
            f"fixture case_id '{fixture_case_id}' does not match requested case_id '{case_id}'"
        )
    if input_source not in SYNTHETIC_FIXTURE_INPUT_SOURCES:
        raise ValueError("fixture input_source must identify an approved synthetic control")

    manifest_path = _fixture_relative_path(
        fixture_path=resolved_fixture,
        value=payload.get("manifest"),
        field_name="manifest",
    )
    manifest = read_manifest(manifest_path)
    if manifest.case_id != case_id:
        raise ValueError(
            f"fixture manifest case_id '{manifest.case_id}' does not match requested "
            f"case_id '{case_id}'"
        )
    case_root = Path(manifest.case_root).resolve()
    if not is_relative_to(case_root, resolved_fixture.parent.resolve()):
        raise ValueError("fixture manifest case_root must stay under the fixture directory")
    induced_rows = payload.get("induced_findings", [])
    if not isinstance(induced_rows, list) or not all(
        isinstance(item, dict) for item in induced_rows
    ):
        raise ValueError("fixture induced_findings must be a list of objects")
    induced_findings = [_normalize_induced_finding(dict(row)) for row in induced_rows]

    return AgentFixtureSpec(
        fixture_id=fixture_id,
        case_id=case_id,
        input_source=input_source,
        manifest_path=manifest_path,
        induced_findings=induced_findings,
    )


def _event_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("events", payload.get("normalized_events"))
    if not isinstance(rows, list):
        raise ValueError("normalized parser output must contain an events list")
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("normalized parser output events must contain only objects")
    return [dict(row) for row in rows]


def _validate_payload_case_id(case_id: str, payload: dict[str, Any]) -> None:
    payload_case_id = payload.get("case_id")
    if payload_case_id is not None and payload_case_id != case_id:
        raise ValueError(
            f"input case_id '{payload_case_id}' does not match requested case_id '{case_id}'"
        )


def _record_path(path: Path, base: Path) -> str:
    resolved = path.resolve()
    resolved_base = base.resolve()
    if is_relative_to(resolved, resolved_base):
        return resolved.relative_to(resolved_base).as_posix()
    cwd = Path.cwd().resolve()
    if is_relative_to(resolved, cwd):
        return resolved.relative_to(cwd).as_posix()
    return resolved.name


def _output_ref(path: Path, output_dir: Path) -> str:
    return _record_path(path, output_dir)


def _artifact_path(manifest: EvidenceManifest, artifact: EvidenceArtifact) -> Path:
    case_root = Path(manifest.case_root).resolve()
    candidate = Path(artifact.path)
    resolved = candidate.resolve() if candidate.is_absolute() else (case_root / candidate).resolve()
    if not is_relative_to(resolved, case_root):
        raise ValueError(
            f"artifact {artifact.artifact_id} path is outside the manifest case_root"
        )
    if not resolved.exists():
        raise ValueError(f"artifact {artifact.artifact_id} does not exist")
    if resolved.is_dir():
        raise ValueError(f"artifact {artifact.artifact_id} path is a directory")
    return resolved


def _append_agent_audit(
    context: AgentWorkflowContext,
    *,
    action: str,
    run_id: str,
    step: AgentStep | None = None,
    status: str | None = None,
    output_refs: dict[str, str] | None = None,
    error: str | None = None,
) -> None:
    if step is not None:
        record_agent_step_event(
            context.paths.audit_path,
            event_type=action,
            case_id=context.case_id,
            run_id=run_id,
            step=step,
            status=status or step.status.value,
            output_refs=output_refs,
            error=error,
            clock=context.clock,
        )
        return

    append_agent_audit_event(
        context.paths.audit_path,
        event_type=action,
        case_id=context.case_id,
        run_id=run_id,
        status=status or "unknown",
        output_refs=output_refs,
        error=error,
        clock=context.clock,
    )


def _append_agent_audit_prelude(
    context: AgentWorkflowContext,
    *,
    run_id: str,
    events: list[dict[str, Any]] | None,
) -> None:
    for event in events or []:
        event_type = event.get("event_type")
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("audit prelude event_type must be a non-empty string")
        status = event.get("status", "completed")
        if not isinstance(status, str) or not status:
            raise ValueError("audit prelude status must be a non-empty string")
        output_refs = event.get("output_refs")
        if output_refs is not None and not isinstance(output_refs, dict):
            raise ValueError("audit prelude output_refs must be a dictionary")
        extra = event.get("extra")
        if extra is not None and not isinstance(extra, dict):
            raise ValueError("audit prelude extra must be a dictionary")
        append_agent_audit_event(
            context.paths.audit_path,
            event_type=event_type,
            case_id=context.case_id,
            run_id=run_id,
            status=status,
            output_refs=output_refs,
            extra=extra,
            clock=context.clock,
        )


def _progress_phase_for_agent_phase(phase: AgentPhase) -> str | None:
    if phase is AgentPhase.PARSE:
        return "normalize/select"
    if phase is AgentPhase.REPORT:
        return "report"
    return None


def _append_progress(
    context: AgentWorkflowContext,
    *,
    phase: str,
    status: str,
    message: str,
) -> ProgressEvent:
    return append_progress_event(
        context.paths.progress_path,
        case_id=context.case_id,
        phase=phase,
        status=status,
        message=message,
        timestamp=context.clock(),
    )


def _artifact_type_counts(artifacts: list[EvidenceArtifact]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for artifact in artifacts:
        counts[artifact.artifact_type] = counts.get(artifact.artifact_type, 0) + 1
    return dict(sorted(counts.items()))


def _artifact_sort_key(artifact: EvidenceArtifact, *, bounded: bool) -> tuple[int, str, str]:
    priority = (
        BOUNDED_ARTIFACT_TYPE_PRIORITY.get(artifact.artifact_type, 1)
        if bounded
        else 0
    )
    return (priority, artifact.relative_path.casefold(), artifact.artifact_id)


def _remaining_event_capacity(context: AgentWorkflowContext) -> int | None:
    if context.max_normalized_events is None:
        return None
    return max(context.max_normalized_events - len(context.normalized_event_rows), 0)


def _has_event_limit_warning(warnings: list[str]) -> bool:
    return any(EVENT_LIMIT_WARNING_MARKER in warning for warning in warnings)


def _limit_warning(context: AgentWorkflowContext) -> str:
    return (
        f"max_normalized_events={context.max_normalized_events} applied; "
        f"bounded triage emitted {len(context.normalized_event_rows)} normalized "
        "events and skipped remaining events"
    )


def _parser_name_for_artifact(artifact: EvidenceArtifact) -> str | None:
    return PARSER_NAME_BY_ARTIFACT_TYPE.get(artifact.artifact_type)


def _parser_status_for_rows(
    rows: list[dict[str, Any]],
    warnings: list[str],
    errors: list[str],
) -> str:
    if errors and not rows:
        return "failed"
    if warnings or errors:
        return "partial_success"
    return "success"


def _metadata_int(metadata: dict[str, Any], name: str) -> int | None:
    value = metadata.get(name)
    return value if isinstance(value, int) else None


def _metadata_selection_counts(metadata: dict[str, Any]) -> dict[str, int]:
    counts = empty_selection_counts()
    for key in counts:
        value = metadata.get(f"selection_{key}")
        if isinstance(value, int):
            counts[key] = value
    return counts


def _combined_parser_status(results: list[ParserResult], rows: list[dict[str, Any]]) -> str:
    statuses = {result.status for result in results}
    if "failed" in statuses and not rows:
        return "failed"
    if "partial_success" in statuses:
        return "partial_success"
    if "failed" in statuses or ("skipped" in statuses and rows):
        return "partial_success"
    if "skipped" in statuses:
        return "skipped"
    return "success"


def _artifact_rows_from_parser_result(
    *,
    artifact: EvidenceArtifact,
    result: ParserResult,
    max_events: int | None,
) -> ArtifactRows:
    warnings = [f"{artifact.artifact_id}: {warning}" for warning in result.warnings]
    errors = [f"{artifact.artifact_id}: {error}" for error in result.errors]
    if result.status in {"failed", "skipped"} and not result.events:
        errors.append(
            f"{artifact.artifact_id}: parser result status={result.status} produced no events"
        )
    rows = [event.to_dict() for event in result.events]
    return ArtifactRows(
        rows=rows,
        warnings=warnings,
        errors=errors,
        parser_name=result.parser_name,
        parser_status=result.status,
        source_rows_seen=_metadata_int(result.metadata, "source_rows_seen") or len(rows),
        source_events_seen=_metadata_int(result.metadata, "source_events_seen") or len(rows),
        selection_counts=_metadata_selection_counts(result.metadata),
        dropped_due_to_cap=_metadata_int(result.metadata, "dropped_due_to_cap") or 0,
        bounded=(
            max_events is not None
            and (_metadata_int(result.metadata, "source_events_seen") or len(rows)) > len(rows)
        ),
        coverage_gaps=[dict(gap) for gap in result.coverage_gaps],
    )


def _registry_rows_from_results(
    *,
    artifact: EvidenceArtifact,
    results: list[ParserResult],
    max_events: int | None,
) -> ArtifactRows:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    coverage_gaps: list[dict[str, Any]] = []
    source_events_seen = 0
    source_rows_seen = 0
    for result in results:
        result_rows = [event.to_dict() for event in result.events]
        rows.extend(result_rows)
        warnings.extend(f"{artifact.artifact_id}: {warning}" for warning in result.warnings)
        errors.extend(f"{artifact.artifact_id}: {error}" for error in result.errors)
        if result.status in {"failed", "skipped"} and not result.events:
            warning = (
                f"{artifact.artifact_id}: parser result status={result.status} "
                "produced no events"
            )
            if result.artifact_type == "registry_user_activity":
                warnings.append(warning)
            else:
                errors.append(warning)
        coverage_gaps.extend(dict(gap) for gap in result.coverage_gaps)
        source_rows_seen += _metadata_int(result.metadata, "source_rows_seen") or len(result_rows)
        source_events_seen += _metadata_int(result.metadata, "source_events_seen") or len(
            result_rows
        )
    return ArtifactRows(
        rows=rows,
        warnings=warnings,
        errors=errors,
        parser_name="recmd",
        parser_status=_combined_parser_status(results, rows),
        source_rows_seen=source_rows_seen,
        source_events_seen=source_events_seen,
        bounded=(
            max_events is not None
            and source_events_seen > len(rows)
        ),
        coverage_gaps=coverage_gaps,
    )


def _increment_selection_counts(context: AgentWorkflowContext, counts: dict[str, int]) -> None:
    for key, value in counts.items():
        context.selection_counts[key] = context.selection_counts.get(key, 0) + value


def _artifact_coverage(
    artifact: EvidenceArtifact,
    result: ArtifactRows,
) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "source_path": artifact.relative_path,
        "artifact_type": artifact.artifact_type,
        "source_image_id": artifact.source_image_id,
        "source_image_label": artifact.source_image_label,
        "registry_hive_type": artifact.registry_hive_type,
        "profile_id": artifact.profile_id,
        "profile_display_name": artifact.profile_display_name,
        "sanitized_profile_hint": artifact.sanitized_profile_hint,
        "source_candidate_ref": artifact.source_candidate_ref,
        "parser_name": result.parser_name,
        "parser_status": result.parser_status,
        "source_rows_seen": result.source_rows_seen,
        "source_events_seen": result.source_events_seen,
        "normalized_rows_selected": len(result.rows),
        "warnings_count": len(result.warnings),
        "errors_count": len(result.errors),
        "bounded": result.bounded,
        "skip_reason": result.skip_reason,
        "coverage_gaps": list(result.coverage_gaps),
    }


def _skipped_artifact_rows(
    artifact: EvidenceArtifact,
    *,
    parser_status: str,
    reason: str,
) -> ArtifactRows:
    return ArtifactRows(
        rows=[],
        warnings=[f"{artifact.artifact_id}: {reason}"],
        parser_name=_parser_name_for_artifact(artifact),
        parser_status=parser_status,
        skip_reason=reason,
        coverage_gaps=[
            {
                "gap_id": f"gap_{artifact.artifact_id}_skipped",
                "artifact_family": artifact.artifact_type,
                "artifact_type": artifact.artifact_type,
                "source_artifact_id": artifact.artifact_id,
                "reason": parser_status,
                "impact": reason,
                "recommended_next_step": "Review artifact availability and parser support.",
                "profile_id": artifact.profile_id,
            }
        ],
    )


def _run_inventory_phase(context: AgentWorkflowContext) -> dict[str, Any]:
    artifacts = sorted(context.manifest.artifacts, key=lambda item: item.relative_path)
    context.artifacts = [AgentArtifactRef.from_artifact(artifact) for artifact in artifacts]
    return {
        "artifact_count": len(artifacts),
        "artifact_ids": [artifact.artifact_id for artifact in artifacts],
        "artifact_types": _artifact_type_counts(artifacts),
    }


def _parser_result_rows(
    *,
    case_id: str,
    artifact: EvidenceArtifact,
    path: Path,
    max_events: int | None = None,
) -> ArtifactRows:
    result = ParserResult.from_dict(_load_json_object(path))
    if result.case_id != case_id:
        raise ValueError(
            f"parser result {artifact.artifact_id} case_id '{result.case_id}' "
            f"does not match requested case_id '{case_id}'"
        )
    warnings = [f"{artifact.artifact_id}: {warning}" for warning in result.warnings]
    errors = [f"{artifact.artifact_id}: {error}" for error in result.errors]
    if result.status in {"failed", "skipped"} and not result.events:
        errors.append(
            f"{artifact.artifact_id}: parser result status={result.status} produced no events"
        )
    rows = [event.to_dict() for event in result.events]
    source_events_seen = len(rows)
    if max_events is not None and len(rows) > max_events:
        rows = rows[:max_events]
        warnings.append(
            f"max_events={max_events} reached; remaining parser result events "
            "were not normalized"
        )
    return ArtifactRows(
        rows=rows,
        warnings=warnings,
        errors=errors,
        parser_name=result.parser_name,
        parser_status=result.status,
        source_rows_seen=source_events_seen,
        source_events_seen=source_events_seen,
        bounded=max_events is not None and source_events_seen > len(rows),
        dropped_due_to_cap=max(source_events_seen - len(rows), 0),
        coverage_gaps=[dict(gap) for gap in result.coverage_gaps],
    )


def _normalized_event_rows(
    *,
    case_id: str,
    artifact: EvidenceArtifact,
    path: Path,
    max_events: int | None = None,
) -> ArtifactRows:
    payload = _load_json_object(path)
    _validate_payload_case_id(case_id, payload)
    rows = _event_rows(payload)
    source_events_seen = len(rows)
    warnings: list[str] = []
    if max_events is not None and len(rows) > max_events:
        rows = rows[:max_events]
        warnings.append(
            f"max_events={max_events} reached; remaining normalized events "
            "were not loaded"
        )
    return ArtifactRows(
        rows=rows,
        warnings=warnings,
        parser_name=_parser_name_for_artifact(artifact),
        parser_status="partial_success" if warnings else "success",
        source_rows_seen=source_events_seen,
        source_events_seen=source_events_seen,
        bounded=max_events is not None and source_events_seen > len(rows),
        dropped_due_to_cap=max(source_events_seen - len(rows), 0),
    )


def _synthetic_csv_rows(
    *,
    case_id: str,
    artifact: EvidenceArtifact,
    path: Path,
    max_events: int | None = None,
) -> ArtifactRows:
    coverage_gaps: list[dict[str, Any]] = []
    if artifact.artifact_type == "mftecmd_csv":
        events, warnings, errors = normalize_mftecmd_csv(
            csv_path=path,
            case_id=case_id,
            artifact_id=artifact.artifact_id,
            max_events=max_events,
        )
    elif artifact.artifact_type == "recmd_runkeys_csv":
        events, warnings, errors = normalize_recmd_runkeys_csv(
            csv_path=path,
            case_id=case_id,
            artifact_id=artifact.artifact_id,
            max_events=max_events,
        )
    elif artifact.artifact_type == "recmd_user_activity_csv":
        events, warnings, errors, user_activity_gaps = normalize_recmd_user_activity_csv(
            csv_path=path,
            case_id=case_id,
            artifact_id=artifact.artifact_id,
            artifact_type="recentdocs",
            source_id=artifact.source_image_id,
            source_role="disk_image",
            max_events=max_events,
        )
        coverage_gaps = [dict(gap) for gap in user_activity_gaps]
    elif artifact.artifact_type == "amcacheparser_csv":
        events, warnings, errors = normalize_amcache_csv(
            csv_path=path,
            case_id=case_id,
            artifact_id=artifact.artifact_id,
            max_events=max_events,
        )
    else:
        raise ValueError(f"unsupported synthetic CSV artifact type: {artifact.artifact_type}")

    rows = [event.to_dict() for event in events]
    artifact_warnings = [f"{artifact.artifact_id}: {warning}" for warning in warnings]
    artifact_errors = [f"{artifact.artifact_id}: {error}" for error in errors]
    return ArtifactRows(
        rows=rows,
        warnings=artifact_warnings,
        errors=artifact_errors,
        parser_name=_parser_name_for_artifact(artifact),
        parser_status=_parser_status_for_rows(rows, artifact_warnings, artifact_errors),
        source_rows_seen=len(rows) if not _has_event_limit_warning(warnings) else None,
        source_events_seen=len(rows) if not _has_event_limit_warning(warnings) else None,
        bounded=_has_event_limit_warning(warnings),
        coverage_gaps=coverage_gaps,
    )


def _raw_parser_rows(
    *,
    context: AgentWorkflowContext,
    artifact: EvidenceArtifact,
    max_events: int | None = None,
) -> ArtifactRows:
    evidence_root = Path(context.manifest.case_root).resolve()
    resolved_artifact = replace(
        artifact,
        path=str(_artifact_path(context.manifest, artifact)),
    )
    if artifact.artifact_type == "mft":
        result = parse_mft_artifact(
            case_id=context.case_id,
            artifact=resolved_artifact,
            runs_root=context.paths.output_dir,
            evidence_root=evidence_root,
            ledger_path=context.paths.audit_path,
            max_events=max_events,
        )
    elif artifact.artifact_type in {"registry", "registry_hive"}:
        runkey_result = parse_registry_runkeys_artifact(
            case_id=context.case_id,
            artifact=resolved_artifact,
            runs_root=context.paths.output_dir,
            evidence_root=evidence_root,
            ledger_path=context.paths.audit_path,
            max_events=max_events,
        )
        results = [runkey_result]
        remaining = (
            None
            if max_events is None
            else max(max_events - len(runkey_result.events), 0)
        )
        if Path(resolved_artifact.path).name.casefold() == "ntuser.dat" and remaining != 0:
            results.append(
                parse_registry_user_activity_artifact(
                    case_id=context.case_id,
                    artifact=resolved_artifact,
                    runs_root=context.paths.output_dir,
                    evidence_root=evidence_root,
                    ledger_path=context.paths.audit_path,
                    max_events=remaining,
                )
            )
        return _registry_rows_from_results(
            artifact=artifact,
            results=results,
            max_events=max_events,
        )
    elif artifact.artifact_type == "amcache":
        result = parse_amcache_artifact(
            case_id=context.case_id,
            artifact=resolved_artifact,
            runs_root=context.paths.output_dir,
            evidence_root=evidence_root,
            ledger_path=context.paths.audit_path,
            max_events=max_events,
        )
    else:
        raise ValueError(f"unsupported raw parser artifact type: {artifact.artifact_type}")

    return _artifact_rows_from_parser_result(
        artifact=artifact,
        result=result,
        max_events=max_events,
    )


def _rows_for_artifact(
    *,
    context: AgentWorkflowContext,
    artifact: EvidenceArtifact,
    max_events: int | None = None,
) -> ArtifactRows:
    artifact_path = _artifact_path(context.manifest, artifact)
    if artifact.artifact_type in PARSER_RESULT_ARTIFACT_TYPES:
        return _parser_result_rows(
            case_id=context.case_id,
            artifact=artifact,
            path=artifact_path,
            max_events=max_events,
        )
    if artifact.artifact_type in NORMALIZED_EVENT_ARTIFACT_TYPES:
        return _normalized_event_rows(
            case_id=context.case_id,
            artifact=artifact,
            path=artifact_path,
            max_events=max_events,
        )
    if artifact.artifact_type in SYNTHETIC_CSV_ARTIFACT_TYPES:
        return _synthetic_csv_rows(
            case_id=context.case_id,
            artifact=artifact,
            path=artifact_path,
            max_events=max_events,
        )
    if artifact.artifact_type in RAW_PARSER_ARTIFACT_TYPES:
        return _raw_parser_rows(
            context=context,
            artifact=artifact,
            max_events=max_events,
        )
    return _skipped_artifact_rows(
        artifact,
        parser_status="skipped",
        reason=f"unsupported artifact type: {artifact.artifact_type}",
    )


def _forensic_triage_rows_for_artifact(
    *,
    context: AgentWorkflowContext,
    artifact: EvidenceArtifact,
    max_events: int | None,
    anchors: TriageAnchors,
) -> ArtifactRows:
    if artifact.artifact_type == "mftecmd_csv":
        artifact_path = _artifact_path(context.manifest, artifact)
        selection = select_mftecmd_csv_for_triage(
            csv_path=artifact_path,
            case_id=context.case_id,
            artifact_id=artifact.artifact_id,
            max_events=max_events,
            anchors=anchors,
        )
        rows = [event.to_dict() for event in selection.events]
        warnings = [f"{artifact.artifact_id}: {warning}" for warning in selection.warnings]
        errors = [f"{artifact.artifact_id}: {error}" for error in selection.errors]
        return ArtifactRows(
            rows=rows,
            warnings=warnings,
            errors=errors,
            parser_name="mftecmd",
            parser_status=_parser_status_for_rows(rows, warnings, errors),
            source_rows_seen=selection.source_rows_seen,
            source_events_seen=selection.source_events_seen,
            selection_counts=selection.selection_counts,
            dropped_due_to_cap=selection.dropped_due_to_cap,
            bounded=selection.dropped_due_to_cap > 0,
        )

    if artifact.artifact_type == "mft":
        evidence_root = Path(context.manifest.case_root).resolve()
        resolved_artifact = replace(
            artifact,
            path=str(_artifact_path(context.manifest, artifact)),
        )
        result = parse_mft_artifact_for_triage(
            case_id=context.case_id,
            artifact=resolved_artifact,
            runs_root=context.paths.output_dir,
            evidence_root=evidence_root,
            ledger_path=context.paths.audit_path,
            max_events=max_events,
            anchors=anchors,
            case_windows=context.case_windows,
        )
        warnings = [f"{artifact.artifact_id}: {warning}" for warning in result.warnings]
        errors = [f"{artifact.artifact_id}: {error}" for error in result.errors]
        if result.status in {"failed", "skipped"} and not result.events:
            errors.append(
                f"{artifact.artifact_id}: parser result status={result.status} produced no events"
            )
        rows = [event.to_dict() for event in result.events]
        return ArtifactRows(
            rows=rows,
            warnings=warnings,
            errors=errors,
            parser_name=result.parser_name,
            parser_status=result.status,
            source_rows_seen=_metadata_int(result.metadata, "source_rows_seen"),
            source_events_seen=_metadata_int(result.metadata, "source_events_seen"),
            selection_counts=_metadata_selection_counts(result.metadata),
            dropped_due_to_cap=_metadata_int(result.metadata, "dropped_due_to_cap") or 0,
            bounded=(_metadata_int(result.metadata, "dropped_due_to_cap") or 0) > 0,
            coverage_gaps=[dict(gap) for gap in result.coverage_gaps],
        )

    return _rows_for_artifact(
        context=context,
        artifact=artifact,
        max_events=max_events,
    )


def _safe_rows_for_artifact(
    *,
    context: AgentWorkflowContext,
    artifact: EvidenceArtifact,
    max_events: int | None,
    anchors: TriageAnchors | None = None,
) -> ArtifactRows:
    try:
        if anchors is None:
            return _rows_for_artifact(
                context=context,
                artifact=artifact,
                max_events=max_events,
            )
        return _forensic_triage_rows_for_artifact(
            context=context,
            artifact=artifact,
            max_events=max_events,
            anchors=anchors,
        )
    except (FileNotFoundError, ValueError) as exc:
        return _skipped_artifact_rows(
            artifact,
            parser_status="unavailable",
            reason=str(exc),
        )


def _supported_artifacts(context: AgentWorkflowContext) -> list[EvidenceArtifact]:
    return [
        artifact
        for artifact in sorted(
            context.manifest.artifacts,
            key=lambda item: _artifact_sort_key(
                item,
                bounded=context.max_normalized_events is not None,
            ),
        )
        if artifact.artifact_type in SUPPORTED_PARSE_ARTIFACT_TYPES
    ]


def _record_artifact_rows(
    context: AgentWorkflowContext,
    artifact: EvidenceArtifact,
    result: ArtifactRows,
    *,
    rows: list[dict[str, Any]],
    warnings: list[str],
    errors: list[str],
) -> None:
    rows.extend(result.rows)
    context.artifact_event_counts[artifact.artifact_id] = len(result.rows)
    context.coverage_artifacts.append(_artifact_coverage(artifact, result))
    warnings.extend(result.warnings)
    errors.extend(result.errors)
    _increment_selection_counts(context, result.selection_counts)
    if result.dropped_due_to_cap:
        context.normalized_event_limit_reached = True


def _record_unprocessed_artifacts(
    context: AgentWorkflowContext,
    artifacts: list[EvidenceArtifact],
    *,
    start_index: int,
    reason: str,
    warnings: list[str],
) -> None:
    for artifact in artifacts[start_index:]:
        result = _skipped_artifact_rows(
            artifact,
            parser_status="skipped",
            reason=reason,
        )
        context.coverage_artifacts.append(_artifact_coverage(artifact, result))
        warnings.extend(result.warnings)


def _run_parse_phase_first_n(
    context: AgentWorkflowContext,
    supported_artifacts: list[EvidenceArtifact],
    *,
    rows: list[dict[str, Any]],
    warnings: list[str],
    errors: list[str],
) -> None:
    for index, artifact in enumerate(supported_artifacts):
        remaining = _remaining_event_capacity(context)
        if remaining == 0:
            context.normalized_event_limit_reached = True
            _record_unprocessed_artifacts(
                context,
                supported_artifacts,
                start_index=index,
                reason="max_normalized_events cap reached before this artifact",
                warnings=warnings,
            )
            break

        result = _safe_rows_for_artifact(
            context=context,
            artifact=artifact,
            max_events=remaining,
        )
        _record_artifact_rows(
            context,
            artifact,
            result,
            rows=rows,
            warnings=warnings,
            errors=errors,
        )
        if _has_event_limit_warning(result.warnings):
            context.normalized_event_limit_reached = True
        if (
            context.max_normalized_events is not None
            and len(rows) >= context.max_normalized_events
            and index < len(supported_artifacts) - 1
        ):
            context.normalized_event_limit_reached = True
            _record_unprocessed_artifacts(
                context,
                supported_artifacts,
                start_index=index + 1,
                reason="max_normalized_events cap reached before this artifact",
                warnings=warnings,
            )
            break


def _run_parse_phase_forensic_triage(
    context: AgentWorkflowContext,
    supported_artifacts: list[EvidenceArtifact],
    *,
    rows: list[dict[str, Any]],
    warnings: list[str],
    errors: list[str],
) -> None:
    anchors = TriageAnchors()
    high_signal = [
        artifact
        for artifact in supported_artifacts
        if artifact.artifact_type not in HIGH_VOLUME_MFT_ARTIFACT_TYPES
    ]
    high_volume = [
        artifact
        for artifact in supported_artifacts
        if artifact.artifact_type in HIGH_VOLUME_MFT_ARTIFACT_TYPES
    ]
    ordered_artifacts = [*high_signal, *high_volume]

    for index, artifact in enumerate(ordered_artifacts):
        remaining = _remaining_event_capacity(context)
        if remaining == 0:
            context.normalized_event_limit_reached = True
            _record_unprocessed_artifacts(
                context,
                ordered_artifacts,
                start_index=index,
                reason="max_normalized_events cap reached before this artifact",
                warnings=warnings,
            )
            break

        result = _safe_rows_for_artifact(
            context=context,
            artifact=artifact,
            max_events=remaining,
            anchors=anchors,
        )
        if artifact.artifact_type not in HIGH_VOLUME_MFT_ARTIFACT_TYPES:
            selected = len(result.rows)
            result.selection_counts["non_mft_preserved"] = selected
            anchors.extend_rows(result.rows)

        _record_artifact_rows(
            context,
            artifact,
            result,
            rows=rows,
            warnings=warnings,
            errors=errors,
        )
        if (
            context.max_normalized_events is not None
            and len(rows) >= context.max_normalized_events
            and index < len(ordered_artifacts) - 1
        ):
            context.normalized_event_limit_reached = True
            _record_unprocessed_artifacts(
                context,
                ordered_artifacts,
                start_index=index + 1,
                reason="max_normalized_events cap reached before this artifact",
                warnings=warnings,
            )
            break


def _coverage_limitations(context: AgentWorkflowContext) -> list[str]:
    limitations: list[str] = []
    if context.max_normalized_events is not None:
        limitations.append(
            "Normalized events were bounded by max_normalized_events; output is triage, "
            "not exhaustive full-artifact recall."
        )
    if context.normalized_event_limit_reached:
        limitations.append(
            "At least one artifact was truncated, bounded, or skipped after the "
            "normalized event cap was reached."
        )
    if any(
        item["parser_status"] in {"partial_success", "failed"}
        for item in context.coverage_artifacts
    ):
        limitations.append("One or more parser results completed with warnings or errors.")
    if any(
        item["parser_status"] in {"skipped", "unavailable"}
        for item in context.coverage_artifacts
    ):
        limitations.append("One or more optional artifacts were skipped or unavailable.")
    if context.event_selection_profile == EVENT_SELECTION_FORENSIC_TRIAGE:
        limitations.append(
            "Forensic triage prioritizes Registry and Amcache observations before "
            "deterministic MFT selection."
        )
    return sorted(set(limitations), key=lambda value: value.casefold())


def _build_coverage_summary(context: AgentWorkflowContext) -> dict[str, Any]:
    total_source_events_seen = 0
    total_known = False
    user_activity_gaps: list[dict[str, Any]] = []
    for artifact in context.coverage_artifacts:
        value = artifact.get("source_events_seen")
        if isinstance(value, int):
            total_source_events_seen += value
            total_known = True
        gaps = artifact.get("coverage_gaps", [])
        if isinstance(gaps, list):
            user_activity_gaps.extend(
                gap
                for gap in gaps
                if isinstance(gap, dict)
                and gap.get("artifact_family") == "registry_user_activity"
            )
    return {
        "case_id": context.case_id,
        "fixture_id": context.fixture_id,
        "input_source": context.input_source,
        "selection_profile": context.event_selection_profile,
        "max_normalized_events": context.max_normalized_events,
        "normalized_events_written": len(context.normalized_event_rows),
        "total_source_events_seen": total_source_events_seen if total_known else None,
        "per_artifact": list(context.coverage_artifacts),
        "registry_user_activity_gaps": user_activity_gaps,
        "selection_notes": dict(sorted(context.selection_counts.items())),
        "limitations": _coverage_limitations(context),
    }


def _run_parse_phase(context: AgentWorkflowContext) -> dict[str, Any]:
    supported_artifacts = _supported_artifacts(context)
    if not supported_artifacts:
        raise ValueError(
            "manifest contains no supported parser-output artifacts; expected one of "
            f"{sorted(SUPPORTED_PARSE_ARTIFACT_TYPES)}"
        )

    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    context.normalized_event_rows = rows
    context.artifact_event_counts = {}
    context.coverage_artifacts = []
    context.selection_counts = empty_selection_counts()
    context.normalized_event_limit_reached = False
    for artifact in sorted(context.manifest.artifacts, key=lambda item: item.relative_path):
        if artifact.artifact_type in SUPPORTED_PARSE_ARTIFACT_TYPES:
            continue
        skipped = _skipped_artifact_rows(
            artifact,
            parser_status="skipped",
            reason=f"unsupported artifact type: {artifact.artifact_type}",
        )
        context.coverage_artifacts.append(_artifact_coverage(artifact, skipped))
        warnings.extend(skipped.warnings)

    if context.event_selection_profile == EVENT_SELECTION_FORENSIC_TRIAGE:
        _run_parse_phase_forensic_triage(
            context,
            supported_artifacts,
            rows=rows,
            warnings=warnings,
            errors=errors,
        )
    else:
        _run_parse_phase_first_n(
            context,
            supported_artifacts,
            rows=rows,
            warnings=warnings,
            errors=errors,
        )

    if errors and not rows:
        raise ValueError("parser phase produced no events: " + "; ".join(errors))
    if errors:
        warnings.extend(errors)
    if context.normalized_event_limit_reached:
        warnings.append(_limit_warning(context))

    context.normalized_event_rows = rows
    context.warnings.extend(warnings)
    context.coverage_summary = _build_coverage_summary(context)
    _write_json(
        context.paths.normalized_events_path,
        {
            "bounded": context.max_normalized_events is not None,
            "case_id": context.case_id,
            "event_count": len(rows),
            "events": rows,
            "limit_reached": context.normalized_event_limit_reached,
            "max_normalized_events": context.max_normalized_events,
            "parser_artifact_event_counts": context.artifact_event_counts,
            "selection_profile": context.event_selection_profile,
        },
    )
    _write_json(context.paths.coverage_summary_path, context.coverage_summary)

    return {
        "bounded": context.max_normalized_events is not None,
        "coverage_summary": _output_ref(
            context.paths.coverage_summary_path,
            context.paths.output_dir,
        ),
        "event_count": len(rows),
        "limit_reached": context.normalized_event_limit_reached,
        "max_normalized_events": context.max_normalized_events,
        "normalized_events": _output_ref(
            context.paths.normalized_events_path,
            context.paths.output_dir,
        ),
        "parser_artifact_event_counts": context.artifact_event_counts,
        "parser_artifact_ids": [artifact.artifact_id for artifact in supported_artifacts],
        "selection_notes": dict(sorted(context.selection_counts.items())),
        "selection_profile": context.event_selection_profile,
        "warning_count": len(warnings),
    }


def _run_correlate_phase(context: AgentWorkflowContext) -> dict[str, Any]:
    events = load_normalized_timeline_events(
        case_id=context.case_id,
        input_path=context.paths.normalized_events_path,
    )
    context.timelines = build_subject_timelines(events)
    _write_json(
        context.paths.timelines_path,
        {
            "case_id": context.case_id,
            "timeline_count": len(context.timelines),
            "timelines": [timeline.to_dict() for timeline in context.timelines],
        },
    )
    return {
        "event_count": len(events),
        "timeline_count": len(context.timelines),
        "subject_timelines": _output_ref(context.paths.timelines_path, context.paths.output_dir),
    }


def _run_validate_phase(context: AgentWorkflowContext) -> dict[str, Any]:
    candidates = candidates_from_subject_timelines(context.timelines)
    context.validation_results = validate_claim_candidates(candidates)
    context.findings = [result.finding for result in context.validation_results]
    _write_json(
        context.paths.findings_path,
        {
            "case_id": context.case_id,
            "finding_count": len(context.findings),
            "findings": [finding.to_dict() for finding in context.findings],
            "validation_results": [result.to_dict() for result in context.validation_results],
        },
    )
    return {
        "finding_count": len(context.findings),
        "findings": _output_ref(context.paths.findings_path, context.paths.output_dir),
    }


def _run_report_phase(context: AgentWorkflowContext) -> dict[str, Any]:
    limitations = [
        "Generated by the deterministic Elenchos agent runner.",
    ]
    report = render_markdown_report(
        case_id=context.case_id,
        timelines=context.timelines,
        findings=context.findings,
        limitations=limitations,
        coverage_summary=context.coverage_summary,
        progress_events=progress_display_rows(read_progress_events(context.paths.progress_path)),
    )
    context.paths.report_path.write_text(report, encoding="utf-8")
    return {
        "report": _output_ref(context.paths.report_path, context.paths.output_dir),
        "finding_count": len(context.findings),
        "timeline_count": len(context.timelines),
    }


def _append_induced_fixture_findings(
    context: AgentWorkflowContext,
    run: AgentRun,
) -> None:
    if not context.induced_findings or context.induced_findings_applied:
        return

    payload = _load_json_object(context.paths.findings_path)
    rows = payload.get("findings")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("findings output must contain a findings object list")

    existing_ids = {
        row.get("finding_id")
        for row in rows
        if isinstance(row.get("finding_id"), str)
    }
    for induced in context.induced_findings:
        finding_id = induced["finding_id"]
        if finding_id in existing_ids:
            raise ValueError(f"induced finding duplicates existing finding_id: {finding_id}")
        rows.append(dict(induced))
        existing_ids.add(finding_id)

    validation_results = payload.get("validation_results", [])
    if not isinstance(validation_results, list):
        validation_results = []
    for induced in context.induced_findings:
        validation_results.append(
            {
                "finding": dict(induced),
                "original_requested_status": induced["status"],
                "final_status": induced["status"],
                "validation_notes": [
                    "synthetic_control_induced_unsupported_claim",
                ],
                "downgrade_reason": None,
                "rule_name": "synthetic_control",
                "contradiction_evidence_refs": [],
            }
        )

    payload["findings"] = rows
    payload["finding_count"] = len(rows)
    payload["validation_results"] = validation_results
    _write_json(context.paths.findings_path, payload)
    context.induced_findings_applied = True

    append_agent_audit_event(
        context.paths.audit_path,
        event_type="fixture_induced_claim_written",
        case_id=context.case_id,
        run_id=run.run_id,
        phase=AgentPhase.VALIDATE.value,
        step_id="step_validate",
        status="completed",
        output_refs={
            "findings": _output_ref(context.paths.findings_path, context.paths.output_dir),
        },
        extra={
            "fixture_id": context.fixture_id,
            "input_source": context.input_source,
            "induced_finding_count": len(context.induced_findings),
        },
        clock=context.clock,
    )


def _run_verify_phase(context: AgentWorkflowContext, run: AgentRun) -> dict[str, Any]:
    _append_induced_fixture_findings(context, run)
    result = verify_agent_outputs(
        case_id=context.case_id,
        output_dir=context.paths.output_dir,
        agent_run=run,
        audit_log_path=context.paths.audit_path,
        clock=context.clock,
    )
    return result.to_dict()


def _run_phase(
    context: AgentWorkflowContext,
    phase: AgentPhase,
    run: AgentRun,
) -> dict[str, Any]:
    if phase is AgentPhase.INVENTORY:
        return _run_inventory_phase(context)
    if phase is AgentPhase.PARSE:
        return _run_parse_phase(context)
    if phase is AgentPhase.CORRELATE:
        return _run_correlate_phase(context)
    if phase is AgentPhase.VALIDATE:
        return _run_validate_phase(context)
    if phase is AgentPhase.REPORT:
        return _run_report_phase(context)
    if phase is AgentPhase.VERIFY:
        return _run_verify_phase(context, run)
    raise ValueError(f"unsupported agent phase: {phase.value}")


def _step_inputs(context: AgentWorkflowContext, phase: AgentPhase) -> dict[str, Any]:
    if phase is AgentPhase.INVENTORY:
        inputs: dict[str, Any] = {"manifest": context.manifest_path.name}
        if context.input_source is not None:
            inputs["input_source"] = context.input_source
        if context.fixture_id is not None:
            inputs["fixture_id"] = context.fixture_id
        return inputs
    if phase is AgentPhase.PARSE:
        return {
            "artifact_count": context.manifest.artifact_count,
            "event_selection_profile": context.event_selection_profile,
            "max_normalized_events": context.max_normalized_events,
            "supported_artifact_types": sorted(SUPPORTED_PARSE_ARTIFACT_TYPES),
        }
    if phase is AgentPhase.CORRELATE:
        return {
            "normalized_events": _output_ref(
                context.paths.normalized_events_path,
                context.paths.output_dir,
            )
        }
    if phase is AgentPhase.VALIDATE:
        return {
            "subject_timelines": _output_ref(
                context.paths.timelines_path,
                context.paths.output_dir,
            )
        }
    if phase is AgentPhase.REPORT:
        return {"findings": _output_ref(context.paths.findings_path, context.paths.output_dir)}
    if phase is AgentPhase.VERIFY:
        return {
            "agent_run": _output_ref(context.paths.agent_run_path, context.paths.output_dir),
            "audit": _output_ref(context.paths.audit_path, context.paths.output_dir),
        }
    return {}


def _make_step(
    *,
    phase: AgentPhase,
    status: AgentStepStatus,
    timestamp: str,
    inputs: dict[str, Any],
    outputs: dict[str, Any] | None = None,
    error: str | None = None,
    attempt: int = 1,
    max_attempts: int = 1,
) -> AgentStep:
    return AgentStep(
        step_id=f"step_{phase.value}",
        phase=phase,
        status=status,
        attempt=attempt,
        max_attempts=max_attempts,
        started_at=timestamp,
        completed_at=timestamp if status is not AgentStepStatus.RUNNING else None,
        inputs=inputs,
        outputs=outputs or {},
        error=error,
        action=f"elenchos.agent.{phase.value}",
    )


def _run_output_refs(paths: AgentWorkflowPaths) -> dict[str, str]:
    candidates = {
        "audit": paths.audit_path,
        "coverage_summary": paths.coverage_summary_path,
        "normalized_events": paths.normalized_events_path,
        "subject_timelines": paths.timelines_path,
        "findings": paths.findings_path,
        "report": paths.report_path,
        "progress": paths.progress_path,
    }
    refs = {"agent_run": _output_ref(paths.agent_run_path, paths.output_dir)}
    refs.update(
        {
            name: _output_ref(path, paths.output_dir)
            for name, path in candidates.items()
            if path.exists()
        }
    )
    return refs


def _write_agent_run(run: AgentRun, agent_run_path: Path) -> None:
    _write_json(agent_run_path, run.to_dict())


def _verification_failed(outputs: dict[str, Any]) -> bool:
    return outputs.get("status") == VerificationStatus.FAILED.value


def _verification_failure_error(outputs: dict[str, Any], *, after_correction: bool = False) -> str:
    failure_count = outputs.get("failure_count", 0)
    if after_correction:
        return f"verification failed after correction with {failure_count} failure(s)"
    return f"verification failed with {failure_count} failure(s)"


def _retry_parser_output_for_failure(
    context: AgentWorkflowContext,
    failure: VerificationFailure,
) -> bool:
    expected = _output_ref(context.paths.normalized_events_path, context.paths.output_dir)
    if failure.path != expected:
        return False
    _run_parse_phase(context)
    return context.paths.normalized_events_path.exists()


def _finalize_run(
    *,
    context: AgentWorkflowContext,
    run: AgentRun,
    status: AgentRunStatus,
    errors: list[str] | None = None,
) -> AgentRun:
    run.status = status
    run.completed_at = context.clock()
    run.output_refs = _run_output_refs(context.paths)
    run.warnings = list(context.warnings)
    run.errors = list(errors or [])
    run.state.final_status = status
    run.state.artifacts = list(context.artifacts)
    run.state.errors = list(errors or [])
    _write_agent_run(run, context.paths.agent_run_path)
    return run


def run_agent_workflow(
    *,
    case_id: str,
    manifest_path: Path,
    output_dir: Path,
    max_iterations: int,
    max_normalized_events: int | None = None,
    event_selection_profile: str = EVENT_SELECTION_FIRST_N,
    input_source: str | None = None,
    fixture_id: str | None = None,
    induced_findings: list[dict[str, Any]] | None = None,
    audit_prelude_events: list[dict[str, Any]] | None = None,
    case_windows: tuple[CASE_WINDOW, ...] = (),
    clock: Clock = utc_now,
) -> AgentRun:
    case_id = _require_non_empty_string("case_id", case_id)
    if not isinstance(max_iterations, int) or max_iterations <= 0:
        raise ValueError("max_iterations must be a positive integer")
    max_normalized_events = _validate_optional_positive_int(
        "max_normalized_events",
        max_normalized_events,
    )
    event_selection_profile = validate_event_selection_profile(event_selection_profile)

    resolved_manifest_path = _validate_manifest_path(manifest_path)
    manifest = read_manifest(resolved_manifest_path)
    if manifest.case_id != case_id:
        raise ValueError(
            f"manifest case_id '{manifest.case_id}' does not match requested case_id '{case_id}'"
        )
    resolved_output_dir = _validate_output_dir(output_dir, manifest)
    resolved_output_dir.mkdir(parents=True, exist_ok=True)
    paths = _workflow_paths(resolved_output_dir)
    _clear_previous_agent_outputs(paths)

    started_at = clock()
    run_id = f"run_{case_id}"
    plan = build_default_agent_plan(case_id, created_at=started_at)
    state = AgentState(case_id=case_id, final_status=AgentRunStatus.RUNNING)
    run = AgentRun(
        run_id=run_id,
        case_id=case_id,
        status=AgentRunStatus.RUNNING,
        plan=plan,
        state=state,
        started_at=started_at,
        max_iterations=max_iterations,
        max_normalized_events=max_normalized_events,
        event_selection_profile=event_selection_profile,
        input_source=input_source,
    )
    context = AgentWorkflowContext(
        case_id=case_id,
        manifest_path=resolved_manifest_path,
        manifest=manifest,
        paths=paths,
        clock=clock,
        max_normalized_events=max_normalized_events,
        event_selection_profile=event_selection_profile,
        input_source=input_source,
        fixture_id=fixture_id,
        induced_findings=[dict(finding) for finding in induced_findings or []],
        case_windows=case_windows,
    )

    _append_agent_audit_prelude(
        context,
        run_id=run.run_id,
        events=audit_prelude_events,
    )
    _append_agent_audit(
        context,
        action="agent_run_started",
        run_id=run.run_id,
        status=run.status.value,
    )
    _append_progress(
        context,
        phase="run_case",
        status="started",
        message="run_case started",
    )
    if input_source is not None:
        append_agent_audit_event(
            context.paths.audit_path,
            event_type="fixture_input_loaded",
            case_id=context.case_id,
            run_id=run.run_id,
            status="completed",
            output_refs={
                "manifest": _output_ref(context.manifest_path, context.paths.output_dir),
            },
            extra={
                "fixture_id": fixture_id,
                "input_source": input_source,
                "induced_finding_count": len(context.induced_findings),
            },
            clock=context.clock,
        )

    for iteration, phase in enumerate(AGENT_PHASES, start=1):
        if iteration > max_iterations:
            error = (
                f"max_iterations={max_iterations} reached before phase {phase.value}"
            )
            run.errors.append(error)
            _append_agent_audit(
                context,
                action="agent_run_failed",
                run_id=run.run_id,
                status=AgentRunStatus.FAILED.value,
                error=error,
            )
            return _finalize_run(
                context=context,
                run=run,
                status=AgentRunStatus.FAILED,
                errors=list(run.errors),
            )

        timestamp = clock()
        inputs = _step_inputs(context, phase)
        running_step = _make_step(
            phase=phase,
            status=AgentStepStatus.RUNNING,
            timestamp=timestamp,
            inputs=inputs,
        )
        state.attempts[running_step.step_id] = 1
        _append_agent_audit(
            context,
            action="agent_step_started",
            run_id=run.run_id,
            step=running_step,
            status=running_step.status.value,
        )
        progress_phase = _progress_phase_for_agent_phase(phase)
        if progress_phase is not None:
            _append_progress(
                context,
                phase=progress_phase,
                status="started",
                message=f"{progress_phase} started",
            )

        try:
            outputs = _run_phase(context, phase, run)
            if phase is AgentPhase.VERIFY and _verification_failed(outputs):
                verification_error = _verification_failure_error(outputs)
                failed_verify_step = _make_step(
                    phase=phase,
                    status=AgentStepStatus.FAILED,
                    timestamp=timestamp,
                    inputs=inputs,
                    outputs=outputs,
                    error=verification_error,
                    max_attempts=2 if iteration < max_iterations else 1,
                )
                run.steps.append(failed_verify_step)
                _append_agent_audit(
                    context,
                    action="agent_step_failed",
                    run_id=run.run_id,
                    step=failed_verify_step,
                    status=failed_verify_step.status.value,
                    error=verification_error,
                )

                if iteration >= max_iterations:
                    max_iteration_error = (
                        f"max_iterations={max_iterations} reached before self-correction"
                    )
                    record_max_iterations_correction(
                        case_id=context.case_id,
                        agent_run=run,
                        audit_log_path=context.paths.audit_path,
                        clock=context.clock,
                    )
                    state.errors.append(max_iteration_error)
                    run.errors.append(max_iteration_error)
                    continue

                correction_result = apply_self_correction(
                    case_id=context.case_id,
                    output_dir=context.paths.output_dir,
                    agent_run=run,
                    verification_result=VerificationResult.from_dict(outputs),
                    audit_log_path=context.paths.audit_path,
                    inventory_recheck=lambda: _run_inventory_phase(context),
                    parser_retry=lambda failure: _retry_parser_output_for_failure(
                        context,
                        failure,
                    ),
                    clock=context.clock,
                )
                for error in correction_result.errors:
                    state.errors.append(error)
                    run.errors.append(error)

                retry_timestamp = clock()
                retry_step = _make_step(
                    phase=phase,
                    status=AgentStepStatus.RUNNING,
                    timestamp=retry_timestamp,
                    inputs=inputs,
                    attempt=2,
                    max_attempts=2,
                )
                state.attempts[retry_step.step_id] = 2
                _append_agent_audit(
                    context,
                    action="agent_step_started",
                    run_id=run.run_id,
                    step=retry_step,
                    status=retry_step.status.value,
                )
                retry_outputs = _run_verify_phase(context, run)
                retry_error = (
                    _verification_failure_error(retry_outputs, after_correction=True)
                    if _verification_failed(retry_outputs)
                    else None
                )
                retry_completed_step = _make_step(
                    phase=phase,
                    status=(
                        AgentStepStatus.FAILED
                        if retry_error is not None
                        else AgentStepStatus.COMPLETED
                    ),
                    timestamp=retry_timestamp,
                    inputs=inputs,
                    outputs=retry_outputs,
                    error=retry_error,
                    attempt=2,
                    max_attempts=2,
                )
                run.steps.append(retry_completed_step)
                if retry_error is None:
                    state.completed_steps.append(retry_completed_step.step_id)
                else:
                    state.errors.append(retry_error)
                    run.errors.append(retry_error)
                _append_agent_audit(
                    context,
                    action=(
                        "agent_step_failed"
                        if retry_error is not None
                        else "agent_step_completed"
                    ),
                    run_id=run.run_id,
                    step=retry_completed_step,
                    status=retry_completed_step.status.value,
                    error=retry_error,
                )
                continue

            status = AgentStepStatus.COMPLETED
            completed_step = _make_step(
                phase=phase,
                status=status,
                timestamp=timestamp,
                inputs=inputs,
                outputs=outputs,
            )
            run.steps.append(completed_step)
            if status is AgentStepStatus.COMPLETED:
                state.completed_steps.append(completed_step.step_id)
            if progress_phase is not None:
                if progress_phase == "normalize/select":
                    message = (
                        "normalize/select completed with "
                        f"{outputs.get('event_count', 0)} selected event(s)"
                    )
                else:
                    message = f"{progress_phase} completed"
                _append_progress(
                    context,
                    phase=progress_phase,
                    status="completed",
                    message=message,
                )
            _append_agent_audit(
                context,
                action="agent_step_completed",
                run_id=run.run_id,
                step=completed_step,
                status=completed_step.status.value,
                output_refs={
                    key: value
                    for key, value in outputs.items()
                    if key
                    in {
                        "coverage_summary",
                        "normalized_events",
                        "subject_timelines",
                        "findings",
                        "report",
                    }
                    and isinstance(value, str)
                },
            )
        except Exception as exc:
            error = str(exc)
            if progress_phase is not None:
                _append_progress(
                    context,
                    phase=progress_phase,
                    status="failed",
                    message=f"{progress_phase} failed",
                )
            failed_step = _make_step(
                phase=phase,
                status=AgentStepStatus.FAILED,
                timestamp=timestamp,
                inputs=inputs,
                error=error,
            )
            run.steps.append(failed_step)
            state.errors.append(error)
            run.errors.append(error)
            _append_agent_audit(
                context,
                action="agent_step_failed",
                run_id=run.run_id,
                step=failed_step,
                status=failed_step.status.value,
                error=error,
            )
            _append_agent_audit(
                context,
                action="agent_run_failed",
                run_id=run.run_id,
                status=AgentRunStatus.FAILED.value,
                error=error,
            )
            _append_progress(
                context,
                phase="run_case",
                status="failed",
                message="run_case failed",
            )
            return _finalize_run(
                context=context,
                run=run,
                status=AgentRunStatus.FAILED,
                errors=list(run.errors),
            )

    final_status = AgentRunStatus.NEEDS_REVIEW if run.errors else AgentRunStatus.COMPLETED
    _append_progress(
        context,
        phase="run_case",
        status=final_status.value,
        message=f"run_case {final_status.value}",
    )
    _append_agent_audit(
        context,
        action="agent_run_completed",
        run_id=run.run_id,
        status=final_status.value,
        output_refs=_run_output_refs(paths),
    )
    return _finalize_run(
        context=context,
        run=run,
        status=final_status,
        errors=list(run.errors),
    )


def run_agent_fixture_workflow(
    *,
    case_id: str,
    fixture_path: Path,
    output_dir: Path,
    max_iterations: int,
    max_normalized_events: int | None = None,
    event_selection_profile: str = EVENT_SELECTION_FIRST_N,
    clock: Clock = utc_now,
) -> AgentRun:
    spec = load_agent_fixture_spec(fixture_path, case_id=case_id)
    return run_agent_workflow(
        case_id=case_id,
        manifest_path=spec.manifest_path,
        output_dir=output_dir,
        max_iterations=max_iterations,
        max_normalized_events=max_normalized_events,
        event_selection_profile=event_selection_profile,
        input_source=spec.input_source,
        fixture_id=spec.fixture_id,
        induced_findings=spec.induced_findings,
        clock=clock,
    )
