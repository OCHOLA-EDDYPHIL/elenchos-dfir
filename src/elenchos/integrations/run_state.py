from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from elenchos.integrations.prepared_manifest import (
    resolve_prepared_manifest_path,
    validate_prepared_manifest_for_run,
)
from elenchos.integrations.rationale_policy import ALLOWED_ACTIONS
from elenchos.integrations.rationale_schema import RunStateSummary
from elenchos.integrations.rationale_trace import (
    RUN_JOB_FILENAME,
    agent_run_dir_from_output_dir,
    iter_jsonl,
    line_count,
    safe_read_json,
)
from elenchos.integrations.safe_paths import display_path
from elenchos.validation.integrity import INTEGRITY_MANIFEST_NAME

GENERATED_STATE_FILES = (
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
    "validation_summary.json",
    "run_integrity.json",
    INTEGRITY_MANIFEST_NAME,
    "progress.jsonl",
    RUN_JOB_FILENAME,
    "model_rationale.jsonl",
    "policy_decisions.jsonl",
)

UNSUPPORTED_BOUNDARY_TERMS = (
    "theft",
    "stolen",
    "exfiltration",
    "transfer",
    "memory",
    "compromise",
    "malware",
    "attribution",
)
UNSUPPORTED_BOUNDARY_STATUSES = {"not_assessed", "needs_review", "unsupported"}


def inspect_run_state(output_dir: Path) -> RunStateSummary:
    agent_run_dir = agent_run_dir_from_output_dir(output_dir)
    present = {
        filename: (agent_run_dir / filename).exists()
        for filename in GENERATED_STATE_FILES
    }
    basis_files = [
        display_path(agent_run_dir / filename) or filename
        for filename, exists in present.items()
        if exists
    ]
    case_id = _case_id(agent_run_dir)
    finding_counts = _finding_status_counts(agent_run_dir / "findings.json")
    question_counts = _case_question_status_counts(agent_run_dir / "case_questions.json")
    coverage_gap_count = _coverage_gap_count(agent_run_dir / "gap_analysis.json")
    self_correction_count = _self_correction_count(agent_run_dir / "self_correction_events.json")
    validation_status = _validation_status(agent_run_dir)
    active_job = _active_job(agent_run_dir / RUN_JOB_FILENAME)
    prepared_manifest_path, prepared_manifest_validation = _prepared_manifest_state(agent_run_dir)
    claim_boundary_required = _claim_boundary_required(agent_run_dir)
    recommended = _recommended_actions(
        agent_run_dir=agent_run_dir,
        required_outputs_present=present,
        active_job=active_job,
        validation_status=validation_status,
        claim_boundary_required=claim_boundary_required,
        prepared_manifest_path=prepared_manifest_path,
    )
    return RunStateSummary(
        case_id=case_id,
        output_dir=display_path(output_dir) or str(output_dir),
        agent_run_dir=display_path(agent_run_dir),
        required_outputs_present=present,
        finding_status_counts=finding_counts,
        case_question_status_counts=question_counts,
        coverage_gap_count=coverage_gap_count,
        self_correction_count=self_correction_count,
        validation_status=validation_status,
        active_job=active_job,
        recommended_next_actions=recommended,
        allowed_actions=sorted(ALLOWED_ACTIONS),
        claim_boundary_required=claim_boundary_required,
        basis_files=basis_files,
        prepared_manifest_path=prepared_manifest_path,
        prepared_manifest_validation=prepared_manifest_validation,
    )


def _case_id(agent_run_dir: Path) -> str | None:
    for filename in (
        "agent_run.json",
        "coverage_summary.json",
        "findings.json",
        "case_questions.json",
        "gap_analysis.json",
        "performance_summary.json",
    ):
        payload = safe_read_json(agent_run_dir / filename)
        if payload is None:
            continue
        case_id = payload.get("case_id")
        if isinstance(case_id, str) and case_id:
            return case_id
    return None


def _rows(payload: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _finding_status_counts(path: Path) -> dict[str, int]:
    payload = safe_read_json(path)
    if payload is None:
        return {}
    findings = _rows(payload, "findings")
    counts: Counter[str] = Counter()
    for row in findings:
        status = row.get("status")
        if isinstance(status, str):
            counts[status] += 1
    return dict(sorted(counts.items()))


def _case_question_status_counts(path: Path) -> dict[str, int]:
    payload = safe_read_json(path)
    if payload is None:
        return {}
    raw_counts = payload.get("status_counts")
    if isinstance(raw_counts, dict):
        status_counts: dict[str, int] = {}
        for key, value in raw_counts.items():
            if isinstance(key, str) and isinstance(value, int):
                status_counts[key] = value
        return dict(sorted(status_counts.items()))
    counts: Counter[str] = Counter()
    for row in _rows(payload, "questions"):
        status = row.get("status")
        if isinstance(status, str):
            counts[status] += 1
    return dict(sorted(counts.items()))


def _coverage_gap_count(path: Path) -> int:
    payload = safe_read_json(path)
    if payload is None:
        return 0
    total = 0
    for key in (
        "carried_forward_case_prep_gaps",
        "parser_coverage_gaps",
        "missing_parser_eligible_artifacts",
        "skipped_prepared_artifacts",
        "unsupported_areas",
        "unsupported_questions",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            total += len(value)
    if total:
        return total
    gap_count = payload.get("coverage_gap_count")
    return gap_count if isinstance(gap_count, int) and gap_count >= 0 else 0


def _self_correction_count(path: Path) -> int:
    payload = safe_read_json(path)
    if payload is None:
        return 0
    event_count = payload.get("event_count")
    if isinstance(event_count, int) and event_count >= 0:
        return event_count
    return len(_rows(payload, "events"))


def _validation_status(agent_run_dir: Path) -> str | None:
    payload = safe_read_json(agent_run_dir / "validation_summary.json")
    if payload is not None:
        status = payload.get("validation_status")
        if isinstance(status, str) and status:
            return status
    integrity_payload = safe_read_json(agent_run_dir / "run_integrity.json")
    if integrity_payload is not None:
        status = integrity_payload.get("validation_status")
        if isinstance(status, str) and status:
            return status
    return None


def _active_job(path: Path) -> dict[str, Any] | None:
    payload = safe_read_json(path)
    if payload is None:
        return None
    status = payload.get("status")
    if status not in {"starting", "running"}:
        return None
    return dict(payload)


def _prepared_manifest_state(agent_run_dir: Path) -> tuple[str | None, dict[str, Any] | None]:
    try:
        path = resolve_prepared_manifest_path(output_dir=agent_run_dir)
        validation = validate_prepared_manifest_for_run(path)
    except ValueError:
        return None, None
    return display_path(path), validation.to_dict()


def _question_requires_boundary(question: Mapping[str, Any]) -> bool:
    status = question.get("status")
    if status not in UNSUPPORTED_BOUNDARY_STATUSES:
        return False
    text = " ".join(
        str(question.get(key, ""))
        for key in ("question", "question_id", "reason")
    ).casefold()
    gaps = question.get("gaps")
    if isinstance(gaps, list):
        text = f"{text} {' '.join(str(item) for item in gaps)}"
    return any(term in text for term in UNSUPPORTED_BOUNDARY_TERMS)


def _claim_boundary_required(agent_run_dir: Path) -> bool:
    validation = safe_read_json(agent_run_dir / "validation_summary.json")
    if validation is not None and validation.get("claim_boundary_required") is True:
        return True
    gaps = safe_read_json(agent_run_dir / "gap_analysis.json")
    if gaps is not None:
        boundaries = gaps.get("claim_boundaries")
        if isinstance(boundaries, list) and boundaries:
            return True
        unsupported = gaps.get("unsupported_areas")
        if isinstance(unsupported, list):
            for row in unsupported:
                if not isinstance(row, dict):
                    continue
                area = str(row.get("area", "")).casefold()
                status = row.get("status")
                if status in UNSUPPORTED_BOUNDARY_STATUSES and any(
                    term in area for term in UNSUPPORTED_BOUNDARY_TERMS
                ):
                    return True
    questions = safe_read_json(agent_run_dir / "case_questions.json")
    if questions is not None:
        return any(_question_requires_boundary(row) for row in _rows(questions, "questions"))
    return False


def _progress_has_phase(agent_run_dir: Path, phase: str) -> bool:
    path = agent_run_dir / "progress.jsonl"
    if line_count(path) == 0:
        return False
    try:
        rows = iter_jsonl(path)
    except ValueError:
        return False
    return any(row.get("phase") == phase for row in rows)


def _recommended_actions(
    *,
    agent_run_dir: Path,
    required_outputs_present: Mapping[str, bool],
    active_job: Mapping[str, object] | None,
    validation_status: str | None,
    claim_boundary_required: bool,
    prepared_manifest_path: str | None,
) -> list[str]:
    if active_job is not None:
        return ["poll_case_run"]

    if not required_outputs_present.get("agent_run.json"):
        if prepared_manifest_path is not None:
            return ["start_case_run", "run_case"]
        return ["prepare_case"]

    if not required_outputs_present.get("report.md") or not required_outputs_present.get(
        "findings.json"
    ):
        return ["poll_case_run", "finish_case_run"]

    if not _progress_has_phase(agent_run_dir, "summarize_run"):
        return ["summarize_run"]

    if validation_status is None:
        return ["validate_run_outputs"]

    if claim_boundary_required:
        return ["emit_claim_boundary"]

    return ["finalize_report_summary", "stop"]


def load_generated_json(path: Path) -> dict[str, object] | None:
    try:
        return safe_read_json(path)
    except json.JSONDecodeError:
        return None
