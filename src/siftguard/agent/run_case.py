from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from siftguard.agent.audit import append_agent_audit_event
from siftguard.agent.case_manifest_adapter import (
    AdaptedCaseManifest,
    adapt_case_prep_to_evidence_manifest,
)
from siftguard.agent.models import BLOCKED_EXECUTION_KEYS, AgentRun
from siftguard.agent.runner import run_agent_workflow
from siftguard.audit.execution_ledger import utc_now
from siftguard.evidence.manifest import write_manifest
from siftguard.policy.paths import (
    generated_output_display_path,
    is_relative_to,
    validate_generated_output_dir,
)
from siftguard.triage import EVENT_SELECTION_FIRST_N, validate_event_selection_profile

CASEBOOK_YAML_REJECTION = "YAML casebooks are not supported in the final sprint; use JSON."

RUN_CASE_OUTPUTS = (
    "agent_run.json",
    "audit.jsonl",
    "coverage_summary.json",
    "normalized_events.json",
    "subject_timelines.json",
    "findings.json",
    "report.md",
    "decision_trace.json",
    "gap_analysis.json",
    "performance_summary.json",
)

Clock = Callable[[], str]
WorkflowRunner = Callable[..., AgentRun]


@dataclass(slots=True)
class RunCaseResult:
    case_id: str
    run: AgentRun
    output_dir: Path
    artifact_manifest_path: Path
    adapted_manifest_path: Path
    decision_trace_path: Path
    gap_analysis_path: Path
    performance_summary_path: Path
    casebook_path: Path | None


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed {label} JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} JSON must contain an object")
    return payload


def _reject_blocked_keys(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string key")
            if key.casefold() in BLOCKED_EXECUTION_KEYS:
                raise ValueError(f"{path} contains blocked execution key: {key}")
            _reject_blocked_keys(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_blocked_keys(item, path=f"{path}[{index}]")
    elif not isinstance(value, (str, int, float, bool, type(None))):
        raise ValueError(f"{path} contains a non-JSON value")


def load_casebook(casebook_path: Path, *, case_id: str) -> dict[str, Any]:
    if casebook_path.suffix.casefold() in {".yaml", ".yml"}:
        raise ValueError(CASEBOOK_YAML_REJECTION)
    if casebook_path.suffix.casefold() != ".json":
        raise ValueError("casebooks must use .json")
    resolved = casebook_path.resolve()
    if not resolved.exists():
        raise ValueError(f"casebook does not exist: {casebook_path}")
    if resolved.is_dir():
        raise ValueError(f"casebook path is a directory: {casebook_path}")
    payload = _load_json_object(resolved, "casebook")
    _reject_blocked_keys(payload, path="casebook")
    payload_case_id = payload.get("case_id")
    if payload_case_id is not None and payload_case_id != case_id:
        raise ValueError(
            f"casebook case_id '{payload_case_id}' does not match case_id '{case_id}'"
        )
    questions = payload.get("case_questions", [])
    if questions is not None and (
        not isinstance(questions, list)
        or not all(isinstance(question, dict) for question in questions)
    ):
        raise ValueError("casebook.case_questions must be a list of objects")
    return payload


def _resolve_output_path(output_dir: Path, name: str) -> Path:
    path = (output_dir / name).resolve()
    if not is_relative_to(path, output_dir):
        raise ValueError(f"output path '{path}' must stay under output_dir '{output_dir}'")
    return path


def _output_ref(path: Path, output_dir: Path) -> str:
    return path.resolve().relative_to(output_dir.resolve()).as_posix()


def _expected_output_paths(output_dir: Path) -> dict[str, Path]:
    return {name: _resolve_output_path(output_dir, name) for name in RUN_CASE_OUTPUTS}


def _output_statuses(output_dir: Path) -> dict[str, dict[str, Any]]:
    statuses: dict[str, dict[str, Any]] = {}
    for name, path in _expected_output_paths(output_dir).items():
        statuses[name] = {
            "exists": path.exists(),
            "path": name,
            "size_bytes": path.stat().st_size if path.exists() and path.is_file() else 0,
        }
    return statuses


def _lifecycle_prelude_events(
    *,
    adapted: AdaptedCaseManifest,
    casebook: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    parser_artifacts = [
        artifact.artifact_id for artifact in adapted.evidence_manifest.artifacts
    ]
    return [
        {
            "event_type": "run_case_started",
            "status": "started",
            "extra": {
                "artifact_manifest": adapted.case_prep_path.name,
                "input_source": "case_prep_manifest",
            },
        },
        {
            "event_type": "artifact_manifest_loaded",
            "status": "completed",
            "extra": {
                "prepared_artifact_count": len(adapted.prepared_artifacts),
                "source_count": len(adapted.sources),
            },
        },
        {
            "event_type": "provenance_checked",
            "status": "completed",
            "extra": {
                "coverage_gap_count": len(adapted.coverage_gaps),
                "memory_source_count": len(adapted.memory_sources),
            },
        },
        {
            "event_type": "parser_plan_selected",
            "status": "completed",
            "extra": {
                "parser_artifact_ids": parser_artifacts,
                "parser_artifact_count": len(parser_artifacts),
            },
        },
        {
            "event_type": "workflow_started",
            "status": "started",
            "extra": {
                "casebook_present": casebook is not None,
            },
        },
    ]


def _sidecar_output_refs(output_dir: Path) -> dict[str, str]:
    names = {
        "decision_trace": "decision_trace.json",
        "gap_analysis": "gap_analysis.json",
        "performance_summary": "performance_summary.json",
    }
    refs: dict[str, str] = {}
    for key, name in names.items():
        path = output_dir / name
        if path.exists():
            refs[key] = _output_ref(path, output_dir)
    return refs


def _ensure_agent_placeholders(output_dir: Path, *, case_id: str, run: AgentRun) -> None:
    normalized = output_dir / "normalized_events.json"
    if not normalized.exists():
        _write_json(
            normalized,
            {
                "case_id": case_id,
                "event_count": 0,
                "events": [],
                "status": run.status.value,
                "warnings": ["workflow did not produce normalized events"],
            },
        )
    timelines = output_dir / "subject_timelines.json"
    if not timelines.exists():
        _write_json(
            timelines,
            {"case_id": case_id, "timeline_count": 0, "timelines": []},
        )
    findings = output_dir / "findings.json"
    if not findings.exists():
        _write_json(
            findings,
            {
                "case_id": case_id,
                "finding_count": 0,
                "findings": [],
                "validation_results": [],
            },
        )
    coverage = output_dir / "coverage_summary.json"
    if not coverage.exists():
        _write_json(
            coverage,
            {
                "case_id": case_id,
                "limitations": ["workflow did not produce parser coverage"],
                "normalized_events_written": 0,
                "per_artifact": [],
            },
        )
    report = output_dir / "report.md"
    if not report.exists():
        report.write_text(
            f"# Case Report\n\nCase: `{case_id}`\n\nNo validated findings were generated.\n",
            encoding="utf-8",
        )
    agent_run = output_dir / "agent_run.json"
    if not agent_run.exists():
        _write_json(agent_run, run.to_dict())


def _augment_coverage_summary(
    *,
    output_dir: Path,
    adapted: AdaptedCaseManifest,
) -> None:
    path = output_dir / "coverage_summary.json"
    payload = _load_json_object(path, "coverage_summary") if path.exists() else {}
    payload["case_prep"] = {
        "artifact_manifest": _output_ref(adapted.case_prep_path, output_dir)
        if is_relative_to(adapted.case_prep_path, output_dir)
        else adapted.case_prep_path.name,
        "coverage_gaps": list(adapted.coverage_gaps),
        "memory_sources_not_assessed": [
            {
                "source_id": source["source_id"],
                "display_name": source["display_name"],
                "status": "not_assessed",
                "analysis_scope": source.get("analysis_scope"),
                "reason": "memory forensics is out of scope for final submission",
            }
            for source in adapted.memory_sources
        ],
        "skipped_prepared_artifacts": list(adapted.skipped_prepared_artifacts),
    }
    _write_json(path, payload)


def _decision_trace(
    *,
    adapted: AdaptedCaseManifest,
    run: AgentRun,
    casebook: dict[str, Any] | None,
    warnings: list[str],
    clock: Clock,
) -> dict[str, Any]:
    parser_artifacts = [
        artifact.artifact_id for artifact in adapted.evidence_manifest.artifacts
    ]
    return {
        "case_id": adapted.case_id,
        "created_at": clock(),
        "mode": "basic_initial",
        "decisions": [
            {
                "decision_id": "artifact_manifest_intake",
                "status": "completed",
                "rationale": "Loaded JSON case_prep manifest generated by case preparation.",
                "inputs": {"artifact_manifest": adapted.case_prep_path.name},
            },
            {
                "decision_id": "provenance_verification",
                "status": "completed",
                "rationale": "Sources and prepared artifact source IDs were present.",
                "inputs": {
                    "source_count": len(adapted.sources),
                    "memory_source_count": len(adapted.memory_sources),
                },
            },
            {
                "decision_id": "parser_plan_selection",
                "status": "completed",
                "rationale": "Selected available parser-eligible prepared artifacts only.",
                "outputs": {"parser_artifact_ids": parser_artifacts},
            },
            {
                "decision_id": "workflow_execution",
                "status": run.status.value,
                "rationale": "Executed existing deterministic SIFTGuard agent workflow.",
                "outputs": {"step_count": len(run.steps)},
            },
            {
                "decision_id": "final_output_generation",
                "status": "completed",
                "rationale": "Wrote required run-case outputs and initial #116 sidecars.",
            },
        ],
        "casebook_present": casebook is not None,
        "warnings": list(warnings),
        "note": "Detailed decision trace expansion is reserved for #117.",
    }


def _gap_analysis(
    *,
    adapted: AdaptedCaseManifest,
    casebook: dict[str, Any] | None,
    warnings: list[str],
    clock: Clock,
) -> dict[str, Any]:
    missing_prepared = [
        artifact
        for artifact in adapted.prepared_artifacts
        if artifact.get("parser_eligible") is True and artifact.get("status") != "available"
    ]
    return {
        "case_id": adapted.case_id,
        "created_at": clock(),
        "mode": "basic_initial",
        "carried_forward_case_prep_gaps": list(adapted.coverage_gaps),
        "memory_sources": [
            {
                "source_id": source["source_id"],
                "display_name": source["display_name"],
                "status": "not_assessed",
                "analysis_scope": source.get("analysis_scope"),
                "reason": "memory source inventoried only; final scope excludes memory forensics",
            }
            for source in adapted.memory_sources
        ],
        "missing_parser_eligible_artifacts": missing_prepared,
        "skipped_prepared_artifacts": list(adapted.skipped_prepared_artifacts),
        "casebook_present": casebook is not None,
        "case_questions_count": (
            len(casebook.get("case_questions", [])) if casebook is not None else 0
        ),
        "warnings": list(warnings),
        "note": "Full case-question gap analysis is expanded by #117/#121.",
    }


def _performance_summary(
    *,
    output_dir: Path,
    run: AgentRun,
    total_wall_clock_seconds: float,
    clock: Clock,
) -> dict[str, Any]:
    return {
        "case_id": run.case_id,
        "created_at": clock(),
        "mode": "basic_initial",
        "run_id": run.run_id,
        "run_status": run.status.value,
        "total_wall_clock_seconds": total_wall_clock_seconds,
        "phases": [
            {
                "phase": step.phase.value,
                "status": step.status.value,
                "attempt": step.attempt,
                "started_at": step.started_at,
                "completed_at": step.completed_at,
            }
            for step in run.steps
        ],
        "outputs": _output_statuses(output_dir),
        "note": "Detailed benchmark fields are expanded by #119.",
    }


def _write_sidecars(
    *,
    output_dir: Path,
    adapted: AdaptedCaseManifest,
    run: AgentRun,
    casebook: dict[str, Any] | None,
    warnings: list[str],
    total_wall_clock_seconds: float,
    clock: Clock,
) -> tuple[Path, Path, Path]:
    decision_trace_path = output_dir / "decision_trace.json"
    gap_analysis_path = output_dir / "gap_analysis.json"
    performance_summary_path = output_dir / "performance_summary.json"
    _write_json(
        decision_trace_path,
        _decision_trace(
            adapted=adapted,
            run=run,
            casebook=casebook,
            warnings=warnings,
            clock=clock,
        ),
    )
    _write_json(
        gap_analysis_path,
        _gap_analysis(
            adapted=adapted,
            casebook=casebook,
            warnings=warnings,
            clock=clock,
        ),
    )
    _write_json(
        performance_summary_path,
        _performance_summary(
            output_dir=output_dir,
            run=run,
            total_wall_clock_seconds=total_wall_clock_seconds,
            clock=clock,
        ),
    )
    return decision_trace_path, gap_analysis_path, performance_summary_path


def _update_agent_run_output_refs(
    *,
    output_dir: Path,
    run: AgentRun,
    warnings: list[str],
) -> None:
    refs = dict(run.output_refs)
    refs.update(_sidecar_output_refs(output_dir))
    for extra_name in ("adapted_manifest.json",):
        path = output_dir / extra_name
        if path.exists():
            refs[extra_name.removesuffix(".json")] = _output_ref(path, output_dir)
    run.output_refs = refs
    merged_warnings = list(dict.fromkeys([*run.warnings, *warnings]))
    run.warnings = merged_warnings
    payload = run.to_dict()
    _write_json(output_dir / "agent_run.json", payload)


def _append_run_case_completion_events(
    *,
    output_dir: Path,
    run: AgentRun,
    status: str,
    clock: Clock,
) -> None:
    audit_path = output_dir / "audit.jsonl"
    workflow_event = "workflow_failed" if status == "failed" else "workflow_completed"
    output_refs = {
        key: _output_ref(path, output_dir)
        for key, path in _expected_output_paths(output_dir).items()
        if path.exists()
    }
    append_agent_audit_event(
        audit_path,
        event_type=workflow_event,
        case_id=run.case_id,
        run_id=run.run_id,
        status=status,
        output_refs=output_refs,
        clock=clock,
    )
    append_agent_audit_event(
        audit_path,
        event_type="run_case_completed",
        case_id=run.case_id,
        run_id=run.run_id,
        status=status,
        output_refs=output_refs,
        clock=clock,
    )


def run_case_workflow(
    *,
    artifact_manifest_path: Path,
    output_dir: Path,
    case_id: str | None = None,
    casebook_path: Path | None = None,
    max_iterations: int,
    max_normalized_events: int | None = None,
    event_selection_profile: str = EVENT_SELECTION_FIRST_N,
    workflow_runner: WorkflowRunner = run_agent_workflow,
    clock: Clock = utc_now,
) -> RunCaseResult:
    if not isinstance(max_iterations, int) or max_iterations <= 0:
        raise ValueError("max_iterations must be a positive integer")
    if max_normalized_events is not None and (
        not isinstance(max_normalized_events, int) or max_normalized_events < 1
    ):
        raise ValueError("max_normalized_events must be a positive integer when provided")
    event_selection_profile = validate_event_selection_profile(event_selection_profile)

    adapted = adapt_case_prep_to_evidence_manifest(
        case_prep_path=artifact_manifest_path,
        requested_case_id=case_id,
    )
    resolved_output_dir = validate_generated_output_dir(
        output_dir,
        forbidden_roots=(*adapted.source_roots, adapted.case_prep_path.parent),
    )
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    casebook: dict[str, Any] | None = None
    warnings = list(adapted.warnings)
    if casebook_path is None:
        warnings.append("no casebook provided; continuing with manifest-only run-case workflow")
    else:
        casebook = load_casebook(casebook_path, case_id=adapted.case_id)

    adapted_manifest_path = _resolve_output_path(resolved_output_dir, "adapted_manifest.json")
    write_manifest(adapted.evidence_manifest, adapted_manifest_path)

    started = time.monotonic()
    run = workflow_runner(
        case_id=adapted.case_id,
        manifest_path=adapted_manifest_path,
        output_dir=resolved_output_dir,
        max_iterations=max_iterations,
        max_normalized_events=max_normalized_events,
        event_selection_profile=event_selection_profile,
        input_source="case_prep_manifest",
        audit_prelude_events=_lifecycle_prelude_events(adapted=adapted, casebook=casebook),
        clock=clock,
    )
    total_wall_clock_seconds = round(time.monotonic() - started, 3)

    _ensure_agent_placeholders(resolved_output_dir, case_id=adapted.case_id, run=run)
    _augment_coverage_summary(output_dir=resolved_output_dir, adapted=adapted)
    decision_trace_path, gap_analysis_path, performance_summary_path = _write_sidecars(
        output_dir=resolved_output_dir,
        adapted=adapted,
        run=run,
        casebook=casebook,
        warnings=warnings,
        total_wall_clock_seconds=total_wall_clock_seconds,
        clock=clock,
    )
    _update_agent_run_output_refs(
        output_dir=resolved_output_dir,
        run=run,
        warnings=warnings,
    )
    _append_run_case_completion_events(
        output_dir=resolved_output_dir,
        run=run,
        status=run.status.value,
        clock=clock,
    )

    return RunCaseResult(
        case_id=adapted.case_id,
        run=run,
        output_dir=resolved_output_dir,
        artifact_manifest_path=adapted.case_prep_path,
        adapted_manifest_path=adapted_manifest_path,
        decision_trace_path=decision_trace_path,
        gap_analysis_path=gap_analysis_path,
        performance_summary_path=performance_summary_path,
        casebook_path=casebook_path.resolve() if casebook_path is not None else None,
    )


def run_case_output_summary(result: RunCaseResult) -> dict[str, str | int | None]:
    return {
        "case_id": result.case_id,
        "status": result.run.status.value,
        "steps": len(result.run.steps),
        "output_dir": str(result.output_dir),
        "agent_run": str(result.output_dir / "agent_run.json"),
        "audit": str(result.output_dir / "audit.jsonl"),
        "decision_trace": str(result.decision_trace_path),
        "gap_analysis": str(result.gap_analysis_path),
        "performance_summary": str(result.performance_summary_path),
        "casebook": str(result.casebook_path) if result.casebook_path is not None else None,
        "output_dir_display": generated_output_display_path(result.output_dir),
    }
