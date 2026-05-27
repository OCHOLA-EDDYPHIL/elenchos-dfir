from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from siftguard.agent.models import (
    AgentArtifactRef,
    AgentPhase,
    AgentPlan,
    AgentRun,
    AgentRunStatus,
    AgentState,
    AgentStep,
    AgentStepStatus,
)
from siftguard.agent.self_correction import (
    apply_self_correction,
    record_max_iterations_correction,
)
from siftguard.agent.verifier import (
    VerificationFailure,
    VerificationResult,
    VerificationStatus,
    verify_agent_outputs,
)
from siftguard.audit.execution_ledger import append_event, make_event_id, read_events, utc_now
from siftguard.correlation.models import SubjectTimeline
from siftguard.correlation.timeline import build_subject_timelines
from siftguard.evidence.manifest import EvidenceArtifact, EvidenceManifest, read_manifest
from siftguard.parser.amcache import normalize_amcache_csv, parse_amcache_artifact
from siftguard.parser.mft import normalize_mftecmd_csv, parse_mft_artifact
from siftguard.parser.registry_runkeys import (
    normalize_recmd_runkeys_csv,
    parse_registry_runkeys_artifact,
)
from siftguard.parser.result import ParserResult
from siftguard.policy.paths import is_relative_to
from siftguard.reporting.markdown_report import render_markdown_report
from siftguard.validation.claims import (
    ClaimValidationResult,
    candidate_from_subject_timeline,
    validate_claim_candidates,
)
from siftguard.validation.models import Finding
from siftguard.workflows.correlation import load_normalized_timeline_events

Clock = Callable[[], str]

AGENT_PHASES = (
    AgentPhase.INVENTORY,
    AgentPhase.PARSE,
    AgentPhase.CORRELATE,
    AgentPhase.VALIDATE,
    AgentPhase.REPORT,
    AgentPhase.VERIFY,
)

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
    "amcacheparser_csv",
}
RAW_PARSER_ARTIFACT_TYPES = {"mft", "registry", "registry_hive", "amcache"}
SUPPORTED_PARSE_ARTIFACT_TYPES = (
    PARSER_RESULT_ARTIFACT_TYPES
    | NORMALIZED_EVENT_ARTIFACT_TYPES
    | SYNTHETIC_CSV_ARTIFACT_TYPES
    | RAW_PARSER_ARTIFACT_TYPES
)


@dataclass(slots=True)
class AgentWorkflowPaths:
    output_dir: Path
    normalized_events_path: Path
    timelines_path: Path
    findings_path: Path
    report_path: Path
    audit_path: Path
    agent_run_path: Path


@dataclass(slots=True)
class AgentWorkflowContext:
    case_id: str
    manifest_path: Path
    manifest: EvidenceManifest
    paths: AgentWorkflowPaths
    clock: Clock
    artifacts: list[AgentArtifactRef] = field(default_factory=list)
    normalized_event_rows: list[dict[str, Any]] = field(default_factory=list)
    timelines: list[SubjectTimeline] = field(default_factory=list)
    validation_results: list[ClaimValidationResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _require_non_empty_string(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
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
        timelines_path=_resolve_output_path(output_dir, "subject_timelines.json"),
        findings_path=_resolve_output_path(output_dir, "findings.json"),
        report_path=_resolve_output_path(output_dir, "report.md"),
        audit_path=_resolve_output_path(output_dir, "audit.jsonl"),
        agent_run_path=_resolve_output_path(output_dir, "agent_run.json"),
    )


def _clear_previous_agent_outputs(paths: AgentWorkflowPaths) -> None:
    for path in (
        paths.normalized_events_path,
        paths.timelines_path,
        paths.findings_path,
        paths.report_path,
        paths.audit_path,
        paths.agent_run_path,
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


def _plan_step(phase: AgentPhase) -> AgentStep:
    return AgentStep(
        step_id=f"step_{phase.value}",
        phase=phase,
        status=AgentStepStatus.PENDING,
        action=f"siftguard.agent.{phase.value}",
    )


def _build_plan(case_id: str, *, created_at: str) -> AgentPlan:
    return AgentPlan(
        plan_id=f"plan_{case_id}",
        case_id=case_id,
        objective="Run the constrained deterministic SIFTGuard workflow.",
        steps=[_plan_step(phase) for phase in AGENT_PHASES],
        created_at=created_at,
    )


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
    event: dict[str, Any] = {
        "event_id": make_event_id(len(read_events(context.paths.audit_path)) + 1),
        "timestamp_utc": context.clock(),
        "action": action,
        "case_id": context.case_id,
        "run_id": run_id,
    }
    if step is not None:
        event.update(
            {
                "step_id": step.step_id,
                "phase": step.phase.value,
                "attempt": step.attempt,
            }
        )
    if status is not None:
        event["status"] = status
    if output_refs is not None:
        event["output_refs"] = dict(output_refs)
    if error is not None:
        event["error"] = error

    append_event(context.paths.audit_path, event)


def _artifact_type_counts(artifacts: list[EvidenceArtifact]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for artifact in artifacts:
        counts[artifact.artifact_type] = counts.get(artifact.artifact_type, 0) + 1
    return dict(sorted(counts.items()))


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
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
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
    return [event.to_dict() for event in result.events], warnings, errors


def _normalized_event_rows(
    *,
    case_id: str,
    artifact: EvidenceArtifact,
    path: Path,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    payload = _load_json_object(path)
    _validate_payload_case_id(case_id, payload)
    return _event_rows(payload), [], []


def _synthetic_csv_rows(
    *,
    case_id: str,
    artifact: EvidenceArtifact,
    path: Path,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if artifact.artifact_type == "mftecmd_csv":
        events, warnings, errors = normalize_mftecmd_csv(
            csv_path=path,
            case_id=case_id,
            artifact_id=artifact.artifact_id,
        )
    elif artifact.artifact_type == "recmd_runkeys_csv":
        events, warnings, errors = normalize_recmd_runkeys_csv(
            csv_path=path,
            case_id=case_id,
            artifact_id=artifact.artifact_id,
        )
    elif artifact.artifact_type == "amcacheparser_csv":
        events, warnings, errors = normalize_amcache_csv(
            csv_path=path,
            case_id=case_id,
            artifact_id=artifact.artifact_id,
        )
    else:
        raise ValueError(f"unsupported synthetic CSV artifact type: {artifact.artifact_type}")

    return (
        [event.to_dict() for event in events],
        [f"{artifact.artifact_id}: {warning}" for warning in warnings],
        [f"{artifact.artifact_id}: {error}" for error in errors],
    )


def _raw_parser_rows(
    *,
    context: AgentWorkflowContext,
    artifact: EvidenceArtifact,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    evidence_root = Path(context.manifest.case_root).resolve()
    if artifact.artifact_type == "mft":
        result = parse_mft_artifact(
            case_id=context.case_id,
            artifact=artifact,
            runs_root=context.paths.output_dir,
            evidence_root=evidence_root,
            ledger_path=context.paths.audit_path,
        )
    elif artifact.artifact_type in {"registry", "registry_hive"}:
        result = parse_registry_runkeys_artifact(
            case_id=context.case_id,
            artifact=artifact,
            runs_root=context.paths.output_dir,
            evidence_root=evidence_root,
            ledger_path=context.paths.audit_path,
        )
    elif artifact.artifact_type == "amcache":
        result = parse_amcache_artifact(
            case_id=context.case_id,
            artifact=artifact,
            runs_root=context.paths.output_dir,
            evidence_root=evidence_root,
            ledger_path=context.paths.audit_path,
        )
    else:
        raise ValueError(f"unsupported raw parser artifact type: {artifact.artifact_type}")

    warnings = [f"{artifact.artifact_id}: {warning}" for warning in result.warnings]
    errors = [f"{artifact.artifact_id}: {error}" for error in result.errors]
    if result.status in {"failed", "skipped"} and not result.events:
        errors.append(
            f"{artifact.artifact_id}: parser result status={result.status} produced no events"
        )
    return [event.to_dict() for event in result.events], warnings, errors


def _rows_for_artifact(
    *,
    context: AgentWorkflowContext,
    artifact: EvidenceArtifact,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    artifact_path = _artifact_path(context.manifest, artifact)
    if artifact.artifact_type in PARSER_RESULT_ARTIFACT_TYPES:
        return _parser_result_rows(
            case_id=context.case_id,
            artifact=artifact,
            path=artifact_path,
        )
    if artifact.artifact_type in NORMALIZED_EVENT_ARTIFACT_TYPES:
        return _normalized_event_rows(
            case_id=context.case_id,
            artifact=artifact,
            path=artifact_path,
        )
    if artifact.artifact_type in SYNTHETIC_CSV_ARTIFACT_TYPES:
        return _synthetic_csv_rows(
            case_id=context.case_id,
            artifact=artifact,
            path=artifact_path,
        )
    if artifact.artifact_type in RAW_PARSER_ARTIFACT_TYPES:
        return _raw_parser_rows(
            context=context,
            artifact=artifact,
        )
    return [], [], []


def _run_parse_phase(context: AgentWorkflowContext) -> dict[str, Any]:
    supported_artifacts = [
        artifact
        for artifact in sorted(context.manifest.artifacts, key=lambda item: item.relative_path)
        if artifact.artifact_type in SUPPORTED_PARSE_ARTIFACT_TYPES
    ]
    if not supported_artifacts:
        raise ValueError(
            "manifest contains no supported parser-output artifacts; expected one of "
            f"{sorted(SUPPORTED_PARSE_ARTIFACT_TYPES)}"
        )

    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    for artifact in supported_artifacts:
        artifact_rows, artifact_warnings, artifact_errors = _rows_for_artifact(
            context=context,
            artifact=artifact,
        )
        rows.extend(artifact_rows)
        warnings.extend(artifact_warnings)
        errors.extend(artifact_errors)

    if errors and not rows:
        raise ValueError("parser phase produced no events: " + "; ".join(errors))
    if errors:
        warnings.extend(errors)

    context.normalized_event_rows = rows
    context.warnings.extend(warnings)
    _write_json(
        context.paths.normalized_events_path,
        {
            "case_id": context.case_id,
            "event_count": len(rows),
            "events": rows,
        },
    )

    return {
        "event_count": len(rows),
        "normalized_events": _output_ref(
            context.paths.normalized_events_path,
            context.paths.output_dir,
        ),
        "parser_artifact_ids": [artifact.artifact_id for artifact in supported_artifacts],
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
    candidates = [candidate_from_subject_timeline(timeline) for timeline in context.timelines]
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
        "Generated by the deterministic SIFTGuard agent runner.",
    ]
    report = render_markdown_report(
        case_id=context.case_id,
        timelines=context.timelines,
        findings=context.findings,
        limitations=limitations,
    )
    context.paths.report_path.write_text(report, encoding="utf-8")
    return {
        "report": _output_ref(context.paths.report_path, context.paths.output_dir),
        "finding_count": len(context.findings),
        "timeline_count": len(context.timelines),
    }


def _run_verify_phase(context: AgentWorkflowContext, run: AgentRun) -> dict[str, Any]:
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
        return {"manifest": context.manifest_path.name}
    if phase is AgentPhase.PARSE:
        return {
            "artifact_count": context.manifest.artifact_count,
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
        action=f"siftguard.agent.{phase.value}",
    )


def _run_output_refs(paths: AgentWorkflowPaths) -> dict[str, str]:
    candidates = {
        "audit": paths.audit_path,
        "normalized_events": paths.normalized_events_path,
        "subject_timelines": paths.timelines_path,
        "findings": paths.findings_path,
        "report": paths.report_path,
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
    clock: Clock = utc_now,
) -> AgentRun:
    case_id = _require_non_empty_string("case_id", case_id)
    if not isinstance(max_iterations, int) or max_iterations <= 0:
        raise ValueError("max_iterations must be a positive integer")

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
    plan = _build_plan(case_id, created_at=started_at)
    state = AgentState(case_id=case_id, final_status=AgentRunStatus.RUNNING)
    run = AgentRun(
        run_id=f"run_{case_id}",
        case_id=case_id,
        status=AgentRunStatus.RUNNING,
        plan=plan,
        state=state,
        started_at=started_at,
        max_iterations=max_iterations,
    )
    context = AgentWorkflowContext(
        case_id=case_id,
        manifest_path=resolved_manifest_path,
        manifest=manifest,
        paths=paths,
        clock=clock,
    )

    _append_agent_audit(
        context,
        action="agent_run_started",
        run_id=run.run_id,
        status=run.status.value,
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
            _append_agent_audit(
                context,
                action="agent_step_completed",
                run_id=run.run_id,
                step=completed_step,
                status=completed_step.status.value,
                output_refs={
                    key: value
                    for key, value in outputs.items()
                    if key in {"normalized_events", "subject_timelines", "findings", "report"}
                    and isinstance(value, str)
                },
            )
        except Exception as exc:
            error = str(exc)
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
            return _finalize_run(
                context=context,
                run=run,
                status=AgentRunStatus.FAILED,
                errors=list(run.errors),
            )

    final_status = AgentRunStatus.NEEDS_REVIEW if run.errors else AgentRunStatus.COMPLETED
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
