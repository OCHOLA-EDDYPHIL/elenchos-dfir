from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elenchos.agent.audit import append_agent_audit_event
from elenchos.agent.case_manifest_adapter import (
    AdaptedCaseManifest,
    adapt_case_prep_to_evidence_manifest,
)
from elenchos.agent.case_questions import (
    evaluate_case_questions,
    question_mappings_for_findings,
    render_case_question_report,
)
from elenchos.agent.casebook import (
    CASEBOOK_YAML_REJECTION,
    Casebook,
    analysis_window_bounds,
    load_casebook,
)
from elenchos.agent.claim_boundaries import build_self_correction_events
from elenchos.agent.decision_trace import build_decision_trace
from elenchos.agent.gap_analysis import build_gap_analysis
from elenchos.agent.models import AgentRun
from elenchos.agent.runner import run_agent_workflow
from elenchos.agent.user_activity_findings import generate_user_activity_findings
from elenchos.audit.execution_ledger import utc_now
from elenchos.evidence.manifest import write_manifest
from elenchos.policy.paths import (
    generated_output_display_path,
    is_relative_to,
    validate_generated_output_dir,
)
from elenchos.triage import EVENT_SELECTION_FIRST_N, validate_event_selection_profile
from elenchos.validation.integrity import write_integrity_manifest

RUN_CASE_OUTPUTS = (
    "agent_run.json",
    "audit.jsonl",
    "coverage_summary.json",
    "normalized_events.json",
    "subject_timelines.json",
    "findings.json",
    "report.md",
    "case_questions.json",
    "decision_trace.json",
    "gap_analysis.json",
    "self_correction_events.json",
    "performance_summary.json",
)

Clock = Callable[[], str]
WorkflowRunner = Callable[..., AgentRun]

__all__ = [
    "CASEBOOK_YAML_REJECTION",
    "RunCaseResult",
    "load_casebook",
    "run_case_output_summary",
    "run_case_workflow",
]


@dataclass(slots=True)
class RunCaseResult:
    case_id: str
    run: AgentRun
    output_dir: Path
    artifact_manifest_path: Path
    adapted_manifest_path: Path
    case_questions_path: Path
    decision_trace_path: Path
    gap_analysis_path: Path
    self_correction_events_path: Path
    performance_summary_path: Path
    integrity_manifest_path: Path
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
    casebook: Casebook | None,
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
                "casebook_id": casebook.case_id if casebook is not None else None,
                "casebook_reusable_template": (
                    casebook.reusable_template if casebook is not None else None
                ),
            },
        },
    ]


def _sidecar_output_refs(output_dir: Path) -> dict[str, str]:
    names = {
        "case_questions": "case_questions.json",
        "decision_trace": "decision_trace.json",
        "gap_analysis": "gap_analysis.json",
        "self_correction_events": "self_correction_events.json",
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


def _events_from_normalized_output(output_dir: Path) -> list[dict[str, Any]]:
    payload = _load_json_object(output_dir / "normalized_events.json", "normalized_events")
    rows = payload.get("events", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("normalized_events.events must be a list of objects")
    return [dict(row) for row in rows]


def _findings_payload(output_dir: Path) -> dict[str, Any]:
    payload = _load_json_object(output_dir / "findings.json", "findings")
    rows = payload.get("findings", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("findings.findings must be a list of objects")
    return payload


def _empty_case_questions(*, case_id: str, created_at: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "casebook_id": None,
        "created_at": created_at,
        "questions": [],
        "status_counts": {},
        "warnings": ["casebook absent; case-question mapping was not available"],
    }


def _write_case_question_outputs(
    *,
    output_dir: Path,
    adapted: AdaptedCaseManifest,
    casebook: Casebook | None,
    created_at: str,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    case_questions_path = output_dir / "case_questions.json"
    findings_payload = _findings_payload(output_dir)
    findings = [dict(row) for row in findings_payload.get("findings", [])]
    coverage = _load_json_object(output_dir / "coverage_summary.json", "coverage_summary")
    user_activity_findings, user_activity_summary = generate_user_activity_findings(
        adapted=adapted,
        normalized_events=_events_from_normalized_output(output_dir),
        existing_findings=findings,
        coverage_summary=coverage,
        casebook=casebook,
    )
    findings.extend(user_activity_findings)
    if casebook is None:
        case_questions = _empty_case_questions(case_id=adapted.case_id, created_at=created_at)
        mappings: list[dict[str, Any]] = []
    else:
        case_questions = evaluate_case_questions(
            casebook=casebook,
            adapted=adapted,
            normalized_events=_events_from_normalized_output(output_dir),
            findings=findings,
            created_at=created_at,
        )
        mappings = question_mappings_for_findings(
            case_questions=case_questions,
            findings=findings,
        )

    findings_payload["findings"] = findings
    findings_payload["finding_count"] = len(findings)
    findings_payload["case_questions"] = case_questions.get("questions", [])
    findings_payload["question_mappings"] = mappings
    findings_payload["user_activity_summary"] = user_activity_summary
    _write_json(output_dir / "findings.json", findings_payload)
    _write_json(case_questions_path, case_questions)

    if casebook is not None:
        report = render_case_question_report(
            case_id=adapted.case_id,
            case_questions=case_questions,
            findings=findings,
            coverage_summary=coverage,
            adapted=adapted,
            user_activity_summary=user_activity_summary,
        )
        (output_dir / "report.md").write_text(report, encoding="utf-8")

    return case_questions_path, case_questions, user_activity_summary


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
    casebook: Casebook | None,
    case_questions: dict[str, Any] | None,
    user_activity_summary: dict[str, Any] | None,
    warnings: list[str],
    total_wall_clock_seconds: float,
    event_selection_profile: str,
    max_normalized_events: int | None,
    clock: Clock,
) -> tuple[Path, Path, Path, Path]:
    decision_trace_path = output_dir / "decision_trace.json"
    gap_analysis_path = output_dir / "gap_analysis.json"
    self_correction_events_path = output_dir / "self_correction_events.json"
    performance_summary_path = output_dir / "performance_summary.json"
    _write_json(
        decision_trace_path,
        build_decision_trace(
            adapted=adapted,
            run=run,
            casebook=casebook,
            case_questions=case_questions,
            user_activity_summary=user_activity_summary,
            warnings=warnings,
            created_at=clock(),
            event_selection_profile=event_selection_profile,
            max_normalized_events=max_normalized_events,
        ),
    )
    _write_json(
        gap_analysis_path,
        build_gap_analysis(
            adapted=adapted,
            casebook=casebook,
            case_questions=case_questions,
            user_activity_summary=user_activity_summary,
            coverage_summary=_load_json_object(
                output_dir / "coverage_summary.json",
                "coverage_summary",
            ),
            warnings=warnings,
            created_at=clock(),
        ),
    )
    _write_json(
        self_correction_events_path,
        build_self_correction_events(
            case_id=adapted.case_id,
            created_at=clock(),
            casebook=casebook,
            case_questions=case_questions,
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
    # Emit the report-claim -> finding -> event -> tool-execution -> artifact trace map.
    # A pure join over already-written outputs; never blocks a run if inputs are absent.
    try:
        from elenchos.autonomy.trace_map import build_trace_map

        _write_json(output_dir / "trace_map.json", build_trace_map(output_dir, clock=clock))
    except Exception:  # noqa: BLE001 - trace map is derived, non-critical output
        pass
    return (
        decision_trace_path,
        gap_analysis_path,
        self_correction_events_path,
        performance_summary_path,
    )


def _append_user_activity_audit_event(
    *,
    output_dir: Path,
    run: AgentRun,
    user_activity_summary: dict[str, Any],
    clock: Clock,
) -> None:
    append_agent_audit_event(
        output_dir / "audit.jsonl",
        event_type="user_activity_analysis_completed",
        case_id=run.case_id,
        run_id=run.run_id,
        status="completed",
        output_refs={
            "normalized_events": "normalized_events.json",
            "findings": "findings.json",
            "gap_analysis": "gap_analysis.json",
        },
        extra={
            "event_count": user_activity_summary.get("event_count", 0),
            "finding_count": user_activity_summary.get("finding_count", 0),
            "coverage_gap_count": len(user_activity_summary.get("coverage_gaps", [])),
        },
        clock=clock,
    )


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

    casebook: Casebook | None = None
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
        case_windows=analysis_window_bounds(casebook) if casebook is not None else (),
        clock=clock,
    )
    total_wall_clock_seconds = round(time.monotonic() - started, 3)

    _ensure_agent_placeholders(resolved_output_dir, case_id=adapted.case_id, run=run)
    _augment_coverage_summary(output_dir=resolved_output_dir, adapted=adapted)
    case_questions_path, case_questions, user_activity_summary = _write_case_question_outputs(
        output_dir=resolved_output_dir,
        adapted=adapted,
        casebook=casebook,
        created_at=clock(),
    )
    (
        decision_trace_path,
        gap_analysis_path,
        self_correction_events_path,
        performance_summary_path,
    ) = _write_sidecars(
        output_dir=resolved_output_dir,
        adapted=adapted,
        run=run,
        casebook=casebook,
        case_questions=case_questions,
        user_activity_summary=user_activity_summary,
        warnings=warnings,
        total_wall_clock_seconds=total_wall_clock_seconds,
        event_selection_profile=event_selection_profile,
        max_normalized_events=max_normalized_events,
        clock=clock,
    )
    _append_user_activity_audit_event(
        output_dir=resolved_output_dir,
        run=run,
        user_activity_summary=user_activity_summary,
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
    integrity_manifest_path = write_integrity_manifest(resolved_output_dir)

    return RunCaseResult(
        case_id=adapted.case_id,
        run=run,
        output_dir=resolved_output_dir,
        artifact_manifest_path=adapted.case_prep_path,
        adapted_manifest_path=adapted_manifest_path,
        case_questions_path=case_questions_path,
        decision_trace_path=decision_trace_path,
        gap_analysis_path=gap_analysis_path,
        self_correction_events_path=self_correction_events_path,
        performance_summary_path=performance_summary_path,
        integrity_manifest_path=integrity_manifest_path,
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
        "case_questions": str(result.case_questions_path),
        "decision_trace": str(result.decision_trace_path),
        "gap_analysis": str(result.gap_analysis_path),
        "self_correction_events": str(result.self_correction_events_path),
        "performance_summary": str(result.performance_summary_path),
        "integrity_manifest": str(result.integrity_manifest_path),
        "progress": str(result.output_dir / "progress.jsonl")
        if (result.output_dir / "progress.jsonl").exists()
        else None,
        "casebook": str(result.casebook_path) if result.casebook_path is not None else None,
        "output_dir_display": generated_output_display_path(result.output_dir),
    }
