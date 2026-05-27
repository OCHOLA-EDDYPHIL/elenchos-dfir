from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from siftguard.agent.models import (
    AgentCorrection,
    AgentRun,
    CorrectionAction,
    CorrectionTrigger,
)
from siftguard.agent.verifier import (
    VerificationFailure,
    VerificationFailureKind,
    VerificationResult,
)
from siftguard.audit.execution_ledger import append_event, make_event_id, read_events, utc_now
from siftguard.correlation.models import SubjectTimeline, TimelineEvent
from siftguard.policy.paths import is_relative_to
from siftguard.reporting.markdown_report import render_markdown_report
from siftguard.validation.models import EvidenceRef, Finding

Clock = Callable[[], str]
InventoryRecheck = Callable[[], dict[str, Any]]
ParserRetry = Callable[[VerificationFailure], bool]


@dataclass(slots=True)
class SelfCorrectionResult:
    case_id: str
    corrected: bool
    corrections: list[AgentCorrection] = field(default_factory=list)
    output_refs: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "corrected": self.corrected,
            "correction_count": len(self.corrections),
            "corrections": [correction.to_dict() for correction in self.corrections],
            "output_refs": dict(self.output_refs),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def _load_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return payload


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _resolve_output_ref(output_dir: Path, ref: str) -> Path:
    candidate = Path(ref)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (output_dir / candidate).resolve()
    )
    if not is_relative_to(resolved, output_dir):
        raise ValueError(f"output reference must stay under output_dir: {ref}")
    return resolved


def _relative_output_ref(output_dir: Path, path: Path) -> str:
    resolved = path.resolve()
    if is_relative_to(resolved, output_dir):
        return resolved.relative_to(output_dir).as_posix()
    return resolved.name


def _findings_ref(agent_run: AgentRun) -> str | None:
    if "findings" in agent_run.output_refs:
        return agent_run.output_refs["findings"]
    for step in agent_run.steps:
        value = step.outputs.get("findings")
        if isinstance(value, str):
            return value
    return None


def _report_ref(agent_run: AgentRun) -> str | None:
    if "report" in agent_run.output_refs:
        return agent_run.output_refs["report"]
    for step in agent_run.steps:
        value = step.outputs.get("report")
        if isinstance(value, str):
            return value
    return None


def _timelines_ref(agent_run: AgentRun) -> str | None:
    if "subject_timelines" in agent_run.output_refs:
        return agent_run.output_refs["subject_timelines"]
    for step in agent_run.steps:
        value = step.outputs.get("subject_timelines")
        if isinstance(value, str):
            return value
    return None


def _append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _failure_ids(
    result: VerificationResult,
    kinds: set[VerificationFailureKind],
) -> set[str]:
    return {
        failure.finding_id
        for failure in result.failures
        if failure.kind in kinds and failure.finding_id is not None
    }


def _evidence_refs_from_finding(finding: dict[str, Any]) -> list[EvidenceRef]:
    refs = finding.get("evidence_refs", [])
    if not isinstance(refs, list):
        return []
    evidence_refs: list[EvidenceRef] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        try:
            evidence_refs.append(EvidenceRef.from_dict(ref))
        except (KeyError, TypeError, ValueError):
            continue
    return evidence_refs


def _correction_id(agent_run: AgentRun, corrections: list[AgentCorrection]) -> str:
    return f"correction_{len(agent_run.corrections) + len(corrections) + 1:06d}"


def _make_correction(
    *,
    agent_run: AgentRun,
    corrections: list[AgentCorrection],
    trigger: CorrectionTrigger,
    diagnosis: str,
    action: CorrectionAction,
    result: str,
    created_at: str,
    related_step_id: str | None,
    evidence_refs: list[EvidenceRef] | None = None,
) -> AgentCorrection:
    return AgentCorrection(
        correction_id=_correction_id(agent_run, corrections),
        trigger=trigger,
        diagnosis=diagnosis,
        action=action,
        result=result,
        created_at=created_at,
        related_step_id=related_step_id,
        evidence_refs=list(evidence_refs or []),
    )


def _append_correction_events(
    *,
    audit_log_path: Path,
    case_id: str,
    corrections: list[AgentCorrection],
    output_refs: dict[str, str],
    clock: Clock,
) -> None:
    def append(action: str, payload: dict[str, Any]) -> None:
        event = {
            "event_id": make_event_id(len(read_events(audit_log_path)) + 1),
            "timestamp_utc": clock(),
            "action": action,
            "case_id": case_id,
            **payload,
        }
        append_event(audit_log_path, event)

    append("correction_started", {"status": "running"})
    for correction in corrections:
        action = (
            "correction_not_applicable"
            if correction.action is CorrectionAction.BLOCK_FINALIZATION
            else "correction_applied"
        )
        append(
            action,
            {
                "status": "completed",
                "correction": correction.to_dict(),
                "output_refs": dict(output_refs),
            },
        )
    append(
        "correction_completed",
        {
            "status": "completed",
            "correction_count": len(corrections),
            "output_refs": dict(output_refs),
        },
    )


def _load_findings_payload(
    output_dir: Path,
    agent_run: AgentRun,
) -> tuple[Path | None, dict[str, Any] | None]:
    ref = _findings_ref(agent_run)
    if ref is None:
        return None, None
    path = _resolve_output_ref(output_dir, ref)
    if not path.exists():
        return path, None
    return path, _load_json_object(path)


def _load_timelines(output_dir: Path, agent_run: AgentRun) -> list[SubjectTimeline]:
    ref = _timelines_ref(agent_run)
    if ref is None:
        return []
    path = _resolve_output_ref(output_dir, ref)
    if not path.exists():
        return []
    payload = _load_json_object(path)
    rows = payload.get("timelines", [])
    if not isinstance(rows, list):
        return []
    timelines: list[SubjectTimeline] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            timelines.append(
                SubjectTimeline(
                    subject=row["subject"],
                    events=[
                        TimelineEvent.from_dict(event)
                        for event in row.get("events", [])
                        if isinstance(event, dict)
                    ],
                    ambiguous=bool(row.get("ambiguous", False)),
                    ambiguity_reason=row.get("ambiguity_reason"),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return timelines


def _validated_findings(rows: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for row in rows:
        try:
            findings.append(Finding.from_dict(row))
        except (KeyError, TypeError, ValueError):
            continue
    return findings


def _update_validation_results(
    payload: dict[str, Any],
    corrected_by_id: dict[str, dict[str, Any]],
    diagnosis: str,
) -> None:
    rows = payload.get("validation_results")
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        finding = row.get("finding")
        if not isinstance(finding, dict):
            continue
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or finding_id not in corrected_by_id:
            continue
        row["finding"] = dict(corrected_by_id[finding_id])
        row["final_status"] = "needs_review"
        row["downgrade_reason"] = diagnosis
        notes = row.get("validation_notes", [])
        if not isinstance(notes, list):
            notes = []
        _append_unique(notes, f"self_correction={diagnosis}")
        row["validation_notes"] = notes


def _rewrite_report(
    *,
    case_id: str,
    output_dir: Path,
    agent_run: AgentRun,
    findings: list[dict[str, Any]],
) -> dict[str, str]:
    report_ref = _report_ref(agent_run)
    if report_ref is None:
        return {}
    report_path = _resolve_output_ref(output_dir, report_ref)
    report = render_markdown_report(
        case_id=case_id,
        timelines=_load_timelines(output_dir, agent_run),
        findings=_validated_findings(findings),
        limitations=[
            "Generated by the deterministic SIFTGuard agent runner.",
            "Self-correction policy reviewed generated findings and report output.",
        ],
    )
    report_path.write_text(report, encoding="utf-8")
    return {"report": _relative_output_ref(output_dir, report_path)}


def _downgrade_unsupported_findings(
    *,
    case_id: str,
    output_dir: Path,
    agent_run: AgentRun,
    verification_result: VerificationResult,
    corrections: list[AgentCorrection],
    clock: Clock,
) -> tuple[bool, dict[str, str]]:
    target_ids = _failure_ids(
        verification_result,
        {
            VerificationFailureKind.MISSING_EVIDENCE_REFS,
            VerificationFailureKind.UNSUPPORTED_CONFIRMED_FINDING,
        },
    )
    if not target_ids:
        return False, {}

    findings_path, payload = _load_findings_payload(output_dir, agent_run)
    if findings_path is None or payload is None:
        return False, {}
    rows = payload.get("findings")
    if not isinstance(rows, list):
        return False, {}

    changed = False
    corrected_by_id: dict[str, dict[str, Any]] = {}
    diagnosis = "finding lacks evidence support required for confirmed or inferred status"
    for row in rows:
        if not isinstance(row, dict):
            continue
        finding_id = row.get("finding_id")
        status = row.get("status")
        if finding_id not in target_ids or status not in {"confirmed", "inferred"}:
            continue

        evidence_refs = _evidence_refs_from_finding(row)
        row["status"] = "needs_review"
        row["supports_final_report"] = False
        rationale = row.get("rationale")
        if not isinstance(rationale, str) or not rationale:
            row["rationale"] = (
                "Self-correction requires analyst review because evidence support "
                "is incomplete."
            )
        limitations = row.get("limitations", [])
        if not isinstance(limitations, list):
            limitations = []
        _append_unique(limitations, diagnosis)
        row["limitations"] = limitations

        correction = _make_correction(
            agent_run=agent_run,
            corrections=corrections,
            trigger=CorrectionTrigger.UNSUPPORTED_FINDING,
            diagnosis=f"Finding {finding_id} was {status} but failed verification: {diagnosis}.",
            action=CorrectionAction.DOWNGRADE_FINDING,
            result="Finding status changed to needs_review.",
            created_at=clock(),
            related_step_id="step_verify",
            evidence_refs=evidence_refs,
        )
        corrections.append(correction)
        corrected_by_id[str(finding_id)] = dict(row)
        changed = True

    if not changed:
        return False, {}

    payload["findings"] = rows
    payload["finding_count"] = len(rows)
    _update_validation_results(payload, corrected_by_id, diagnosis)
    _write_json(findings_path, payload)
    output_refs = {"findings": _relative_output_ref(output_dir, findings_path)}
    output_refs.update(
        _rewrite_report(
            case_id=case_id,
            output_dir=output_dir,
            agent_run=agent_run,
            findings=[dict(row) for row in rows if isinstance(row, dict)],
        )
    )
    return True, output_refs


def _regenerate_report_only(
    *,
    case_id: str,
    output_dir: Path,
    agent_run: AgentRun,
    verification_result: VerificationResult,
    corrections: list[AgentCorrection],
    clock: Clock,
) -> tuple[bool, dict[str, str]]:
    failures = [
        failure
        for failure in verification_result.failures
        if failure.kind is VerificationFailureKind.REPORTED_FINDING_MISSING
    ]
    if not failures:
        return False, {}

    findings_path, payload = _load_findings_payload(output_dir, agent_run)
    if findings_path is None or payload is None:
        return False, {}
    rows = payload.get("findings")
    if not isinstance(rows, list):
        return False, {}

    output_refs = _rewrite_report(
        case_id=case_id,
        output_dir=output_dir,
        agent_run=agent_run,
        findings=[dict(row) for row in rows if isinstance(row, dict)],
    )
    if not output_refs:
        return False, {}

    missing_ids = ", ".join(
        sorted(
            failure.finding_id or "unknown"
            for failure in failures
        )
    )
    corrections.append(
        _make_correction(
            agent_run=agent_run,
            corrections=corrections,
            trigger=CorrectionTrigger.INVALID_OUTPUT,
            diagnosis=f"Report referenced findings absent from validated findings: {missing_ids}.",
            action=CorrectionAction.RETRY,
            result="Report regenerated from validated findings.",
            created_at=clock(),
            related_step_id="step_report",
        )
    )
    return True, output_refs


def _retry_missing_parser_outputs(
    *,
    agent_run: AgentRun,
    verification_result: VerificationResult,
    parser_retry: ParserRetry | None,
    corrections: list[AgentCorrection],
    clock: Clock,
) -> tuple[bool, dict[str, str]]:
    failures = [
        failure
        for failure in verification_result.failures
        if failure.kind is VerificationFailureKind.MISSING_PARSER_OUTPUT
    ]
    if not failures:
        return False, {}

    corrected = False
    for failure in failures:
        retried = parser_retry(failure) if parser_retry is not None else False
        action = CorrectionAction.RETRY if retried else CorrectionAction.BLOCK_FINALIZATION
        result = (
            "Parser output regenerated through constrained internal parser phase."
            if retried
            else "Parser output could not be regenerated safely in this correction cycle."
        )
        corrections.append(
            _make_correction(
                agent_run=agent_run,
                corrections=corrections,
                trigger=CorrectionTrigger.MISSING_OUTPUT,
                diagnosis=failure.message,
                action=action,
                result=result,
                created_at=clock(),
                related_step_id=failure.step_id,
            )
        )
        corrected = corrected or retried
    return corrected, {}


def _recheck_inventory_for_missing_evidence(
    *,
    agent_run: AgentRun,
    verification_result: VerificationResult,
    inventory_recheck: InventoryRecheck | None,
    corrections: list[AgentCorrection],
    clock: Clock,
) -> None:
    if not any(
        failure.kind is VerificationFailureKind.MISSING_EVIDENCE_REFS
        for failure in verification_result.failures
    ):
        return

    if inventory_recheck is None:
        result = "Inventory re-check was unavailable; findings remain needs_review."
    else:
        inventory_result = inventory_recheck()
        artifact_count = inventory_result.get("artifact_count", "unknown")
        result = f"Inventory rechecked before finalization; artifact_count={artifact_count}."

    corrections.append(
        _make_correction(
            agent_run=agent_run,
            corrections=corrections,
            trigger=CorrectionTrigger.MISSING_OUTPUT,
            diagnosis="Verification found missing evidence references.",
            action=CorrectionAction.RECHECK_INVENTORY,
            result=result,
            created_at=clock(),
            related_step_id="step_inventory",
        )
    )


def apply_self_correction(
    *,
    case_id: str,
    output_dir: Path,
    agent_run: AgentRun,
    verification_result: VerificationResult,
    audit_log_path: Path | None = None,
    inventory_recheck: InventoryRecheck | None = None,
    parser_retry: ParserRetry | None = None,
    clock: Clock = utc_now,
) -> SelfCorrectionResult:
    if agent_run.case_id != case_id:
        raise ValueError("agent_run case_id must match correction case_id")
    if verification_result.case_id != case_id:
        raise ValueError("verification_result case_id must match correction case_id")

    resolved_output_dir = output_dir.resolve()
    corrections: list[AgentCorrection] = []
    output_refs: dict[str, str] = {}
    errors: list[str] = []

    try:
        parser_corrected, parser_refs = _retry_missing_parser_outputs(
            agent_run=agent_run,
            verification_result=verification_result,
            parser_retry=parser_retry,
            corrections=corrections,
            clock=clock,
        )
        output_refs.update(parser_refs)

        _recheck_inventory_for_missing_evidence(
            agent_run=agent_run,
            verification_result=verification_result,
            inventory_recheck=inventory_recheck,
            corrections=corrections,
            clock=clock,
        )

        downgraded, downgrade_refs = _downgrade_unsupported_findings(
            case_id=case_id,
            output_dir=resolved_output_dir,
            agent_run=agent_run,
            verification_result=verification_result,
            corrections=corrections,
            clock=clock,
        )
        output_refs.update(downgrade_refs)

        report_corrected, report_refs = _regenerate_report_only(
            case_id=case_id,
            output_dir=resolved_output_dir,
            agent_run=agent_run,
            verification_result=verification_result,
            corrections=corrections,
            clock=clock,
        )
        output_refs.update(report_refs)

        corrected = parser_corrected or downgraded or report_corrected
    except Exception as exc:
        corrected = False
        errors.append(str(exc))
        corrections.append(
            _make_correction(
                agent_run=agent_run,
                corrections=corrections,
                trigger=CorrectionTrigger.INVALID_OUTPUT,
                diagnosis="Self-correction failed while updating generated outputs.",
                action=CorrectionAction.BLOCK_FINALIZATION,
                result=str(exc),
                created_at=clock(),
                related_step_id="step_verify",
            )
        )

    agent_run.corrections.extend(corrections)
    agent_run.state.corrections.extend(corrections)
    if audit_log_path is not None:
        _append_correction_events(
            audit_log_path=audit_log_path,
            case_id=case_id,
            corrections=corrections,
            output_refs=output_refs,
            clock=clock,
        )

    return SelfCorrectionResult(
        case_id=case_id,
        corrected=corrected,
        corrections=corrections,
        output_refs=output_refs,
        errors=errors,
    )


def record_max_iterations_correction(
    *,
    case_id: str,
    agent_run: AgentRun,
    audit_log_path: Path | None = None,
    clock: Clock = utc_now,
) -> AgentCorrection:
    correction = AgentCorrection(
        correction_id=f"correction_{len(agent_run.corrections) + 1:06d}",
        trigger=CorrectionTrigger.MAX_ITERATIONS,
        diagnosis="Verification failed but max_iterations prevented a correction cycle.",
        action=CorrectionAction.BLOCK_FINALIZATION,
        result="Run finalized as needs_review without applying self-correction.",
        created_at=clock(),
        related_step_id="step_verify",
    )
    agent_run.corrections.append(correction)
    agent_run.state.corrections.append(correction)
    if audit_log_path is not None:
        _append_correction_events(
            audit_log_path=audit_log_path,
            case_id=case_id,
            corrections=[correction],
            output_refs={},
            clock=clock,
        )
    return correction
